#endpoints.py
import asyncio
import inspect
import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, File, HTTPException, Request, Response, UploadFile
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models.schemas import (
    URLScanRequest,
    URLScanResponse,
    QRScanResponse,
    MessageScanRequest,
    MessageScanResponse,
    HistoryResponse,
    BatchScanRequest,
    BatchScanItemResult,
    BatchScanResponse,
)
from app.models.database import get_db, ScanAuditLog, SessionLocal
from app.analyzers.url_analyzer import analyze_url, BlockedTarget
from app.analyzers.qr_analyzer import analyze_qr_code
from app.analyzers.text_analyzer import analyze_message_text
from app.services.risk_engine import (
    calculate_url_risk,
    calculate_qr_risk,
    calculate_message_risk,
)
from app.services.ai_explainer import AIExplainer
from app.services.report_generator import ReportGenerator
from app.security import get_owner_id, scan_limiter, batch_limiter, read_limiter, daily_cap

logger = logging.getLogger(__name__)
router = APIRouter()
ai_explainer = AIExplainer()

GENERIC_ERROR = "Something went wrong while scanning. Please try again."
MAX_URL_CHARS = 2048
MAX_MESSAGE_CHARS = 10_000
MAX_QR_BYTES = 5 * 1024 * 1024
MAX_EXPORT_BYTES = 1024 * 1024
MAX_BATCH_ITEMS = 50
BATCH_CONCURRENCY = 10
BATCH_ITEM_TIMEOUT = 20.0  # WHOIS + SSL + redirects can legitimately take ~10s

# Per-IP limit first, then the global daily cap. That order stops one IP from
# draining the global quota with requests its own limit would have rejected.
SCAN_LIMITS = [Depends(scan_limiter), Depends(daily_cap)]


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
async def _resolve(value):
    """Analyzers may be sync or async (tests mock them), so handle both."""
    return await value if inspect.isawaitable(value) else value


async def _explain(evidence, risk_assessment):
    # The Gemini call is blocking, so keep it off the event loop
    return await asyncio.to_thread(
        ai_explainer.generate_explanation, evidence.model_dump(), risk_assessment.model_dump()
    )


def _intel_flagged(url_ev) -> bool:
    ti = getattr(url_ev, "threat_intel", None)
    flagged = ti.get("flagged", False) if isinstance(ti, dict) else getattr(ti, "flagged", False)
    return bool(getattr(url_ev, "safe_browsing_hit", False) or flagged)


def _ml(url_ev) -> float:
    p = getattr(url_ev, "ml_probability", None)
    return float(p) if p is not None else 0.0


def _save(db: Session, owner_id: Optional[str], **fields) -> None:
    """Write to the audit log. A history-write failure must never hide a finished scan."""
    try:
        db.add(ScanAuditLog(owner_id=owner_id, created_at=datetime.now(timezone.utc), **fields))
        db.commit()
    except Exception:
        db.rollback()
        logger.exception("Could not save scan to history")


# --------------------------------------------------------------------------- #
# Single scans
# --------------------------------------------------------------------------- #
@router.post("/scan/url", response_model=URLScanResponse, dependencies=SCAN_LIMITS)
async def scan_url(
    request: URLScanRequest,
    owner_id: Optional[str] = Depends(get_owner_id),
    db: Session = Depends(get_db),
):
    if len(request.url) > MAX_URL_CHARS:
        raise HTTPException(status_code=400, detail=f"That URL is too long (limit {MAX_URL_CHARS} characters).")
    try:
        evidence = await _resolve(analyze_url(request.url))
        risk_assessment = await _resolve(calculate_url_risk(evidence))
        explanation = await _explain(evidence, risk_assessment)

        _save(
            db, owner_id,
            modality="url",
            target=request.url,
            severity_level=risk_assessment.level,
            composite_risk_score=risk_assessment.score,
            heuristic_score=float(risk_assessment.score),
            ml_probability=_ml(evidence),
            intel_feed_hits=1 if _intel_flagged(evidence) else 0,
            ai_explanation=explanation.summary,
            evidence_json=evidence.model_dump(),
        )

        return URLScanResponse(
            url=request.url,
            evidence=evidence,
            risk_assessment=risk_assessment,
            explanation=explanation,
        )
    except BlockedTarget as e:
        raise HTTPException(status_code=400, detail=str(e))
    except HTTPException:
        raise
    except Exception:
        logger.exception("URL scan failed")
        raise HTTPException(status_code=500, detail=GENERIC_ERROR)


@router.post("/scan/qr", response_model=QRScanResponse, dependencies=SCAN_LIMITS)
async def scan_qr(
    file: UploadFile = File(...),
    owner_id: Optional[str] = Depends(get_owner_id),
    db: Session = Depends(get_db),
):
    try:
        content = await file.read(MAX_QR_BYTES + 1)
        if len(content) > MAX_QR_BYTES:
            raise HTTPException(status_code=413, detail="That image is too large. The limit is 5 MB.")

        evidence = await _resolve(analyze_qr_code(content))
        risk_assessment = await _resolve(calculate_qr_risk(evidence))
        explanation = await _explain(evidence, risk_assessment)

        target_str = evidence.extracted_text or file.filename or "Uploaded QR Code"
        url_ev = evidence.url_evidence

        _save(
            db, owner_id,
            modality="qr",
            target=target_str,
            severity_level=risk_assessment.level,
            composite_risk_score=risk_assessment.score,
            heuristic_score=float(risk_assessment.score),
            ml_probability=_ml(url_ev) if url_ev else 0.0,
            intel_feed_hits=1 if url_ev and _intel_flagged(url_ev) else 0,
            ai_explanation=explanation.summary,
            evidence_json=evidence.model_dump(),
        )

        return QRScanResponse(
            evidence=evidence,
            risk_assessment=risk_assessment,
            explanation=explanation,
        )
    except BlockedTarget as e:
        raise HTTPException(status_code=400, detail=str(e))
    except HTTPException:
        raise
    except Exception:
        logger.exception("QR scan failed")
        raise HTTPException(status_code=500, detail=GENERIC_ERROR)


@router.post("/scan/message", response_model=MessageScanResponse, dependencies=SCAN_LIMITS)
async def scan_message(
    request: MessageScanRequest,
    owner_id: Optional[str] = Depends(get_owner_id),
    db: Session = Depends(get_db),
):
    if len(request.message) > MAX_MESSAGE_CHARS:
        raise HTTPException(status_code=400, detail=f"That message is too long (limit {MAX_MESSAGE_CHARS} characters).")
    try:
        evidence = await _resolve(analyze_message_text(request.message))
        risk_assessment = await _resolve(calculate_message_risk(evidence))
        explanation = await _explain(evidence, risk_assessment)

        url_evs = evidence.url_evidences or []

        _save(
            db, owner_id,
            modality="text",
            target=request.message,
            severity_level=risk_assessment.level,
            composite_risk_score=risk_assessment.score,
            heuristic_score=float(risk_assessment.score),
            ml_probability=max((_ml(u) for u in url_evs), default=0.0),
            intel_feed_hits=sum(1 for u in url_evs if _intel_flagged(u)),
            ai_explanation=explanation.summary,
            evidence_json=evidence.model_dump(),
        )

        return MessageScanResponse(
            message=request.message,
            evidence=evidence,
            risk_assessment=risk_assessment,
            explanation=explanation,
        )
    except BlockedTarget as e:
        raise HTTPException(status_code=400, detail=str(e))
    except HTTPException:
        raise
    except Exception:
        logger.exception("Message scan failed")
        raise HTTPException(status_code=500, detail=GENERIC_ERROR)


# --------------------------------------------------------------------------- #
# History (scoped to the browser's anonymous id)
# --------------------------------------------------------------------------- #
def _empty_history() -> HistoryResponse:
    zeros = {"high": 0, "medium": 0, "low": 0, "critical": 0,
             "HIGH": 0, "MEDIUM": 0, "LOW": 0, "CRITICAL": 0}
    return HistoryResponse(total_scans=0, risk_breakdown=zeros, scans=[])


@router.get("/history", response_model=HistoryResponse, dependencies=[Depends(read_limiter)])
def get_scan_history(
    owner_id: Optional[str] = Depends(get_owner_id),
    db: Session = Depends(get_db),
):
    if owner_id is None:  # no visitor id: nothing to show, and never show other people's scans
        return _empty_history()
    try:
        rows = (
            db.query(ScanAuditLog.severity_level, func.count(ScanAuditLog.id))
            .filter(ScanAuditLog.owner_id == owner_id)
            .group_by(ScanAuditLog.severity_level)
            .all()
        )
        counts: dict = {}
        for level, n in rows:
            key = str(level or "").upper()
            counts[key] = counts.get(key, 0) + n

        total_scans = sum(counts.values())
        critical = counts.get("CRITICAL", 0)
        high = counts.get("HIGH", 0) + critical  # "high" means high + critical
        medium = counts.get("MEDIUM", 0)
        low = counts.get("LOW", 0)

        risk_breakdown = {
            "high": high, "medium": medium, "low": low, "critical": critical,
            "HIGH": high, "MEDIUM": medium, "LOW": low, "CRITICAL": critical,
        }

        latest_scans = (
            db.query(ScanAuditLog)
            .filter(ScanAuditLog.owner_id == owner_id)
            .order_by(ScanAuditLog.created_at.desc(), ScanAuditLog.id.desc())
            .limit(50)
            .all()
        )

        return HistoryResponse(
            total_scans=total_scans,
            risk_breakdown=risk_breakdown,
            scans=latest_scans,
        )
    except Exception:
        logger.exception("Could not load scan history")
        raise HTTPException(status_code=500, detail="Could not load scan history.")


@router.delete("/history", dependencies=[Depends(read_limiter)])
def clear_scan_history(
    owner_id: Optional[str] = Depends(get_owner_id),
    db: Session = Depends(get_db),
):
    """Delete every saved scan belonging to this browser."""
    if owner_id is None:
        raise HTTPException(status_code=400, detail="Missing visitor id.")
    try:
        deleted = (
            db.query(ScanAuditLog)
            .filter(ScanAuditLog.owner_id == owner_id)
            .delete(synchronize_session=False)
        )
        db.commit()
        return {"deleted": deleted}
    except Exception:
        db.rollback()
        logger.exception("Could not delete scan history")
        raise HTTPException(status_code=500, detail="Could not delete scan history.")


# --------------------------------------------------------------------------- #
# Batch
# --------------------------------------------------------------------------- #
async def _evaluate_batch_item(scan_type: str, item: str):
    """Returns (evidence, risk_assessment, threat_intel_flagged, ml_probability)."""
    if scan_type == "url":
        evidence = await _resolve(analyze_url(item))
        risk = await _resolve(calculate_url_risk(evidence))
        return evidence, risk, _intel_flagged(evidence), _ml(evidence)

    evidence = await _resolve(analyze_message_text(item))
    risk = await _resolve(calculate_message_risk(evidence))
    url_evs = getattr(evidence, "url_evidences", []) or []
    return (
        evidence,
        risk,
        any(_intel_flagged(u) for u in url_evs),
        max((_ml(u) for u in url_evs), default=0.0),
    )


def _batch_summary(flagged: bool, triggers: list) -> str:
    if flagged:
        return "Flagged by threat intelligence feeds as a known malicious indicator."
    if triggers:
        names = ", ".join(str(t) for t in triggers[:2])
        return f"Flagged {len(triggers)} threat indicators ({names})."
    return "No known risk indicators found."


def _unverified(item: str, summary: str) -> BatchScanItemResult:
    """A scan that couldn't finish must never look safe, so it gets its own level."""
    return BatchScanItemResult(
        target=item,
        risk_score=0,
        risk_level="UNKNOWN",
        flags_count=0,
        summary=summary,
        threat_intel_flagged=False,
    )


@router.post("/scan/batch", response_model=BatchScanResponse, dependencies=[Depends(batch_limiter)])
async def scan_batch(
    request: BatchScanRequest,
    http_request: Request,
    owner_id: Optional[str] = Depends(get_owner_id),
):
    """Scan up to 50 URLs or messages concurrently (semaphore-limited)."""
    if request.scan_type not in ("url", "message"):
        raise HTTPException(status_code=400, detail="scan_type must be 'url' or 'message'.")

    cleaned_items = [item.strip() for item in request.items if item and item.strip()]
    if not cleaned_items:
        raise HTTPException(status_code=400, detail="No valid items provided for batch scan.")
    if len(cleaned_items) > MAX_BATCH_ITEMS:
        raise HTTPException(status_code=400, detail=f"Maximum {MAX_BATCH_ITEMS} items allowed per batch scan.")
    if any(len(i) > MAX_MESSAGE_CHARS for i in cleaned_items):
        raise HTTPException(status_code=400, detail="One of the items is too long.")

    # A batch costs one scan per item against the global daily cap
    daily_cap.check(http_request, cost=len(cleaned_items))

    semaphore = asyncio.Semaphore(BATCH_CONCURRENCY)

    async def process_single_item(item: str) -> BatchScanItemResult:
        async with semaphore:
            try:
                evidence, risk_assessment, flagged, ml_prob = await asyncio.wait_for(
                    _evaluate_batch_item(request.scan_type, item), timeout=BATCH_ITEM_TIMEOUT
                )
            except asyncio.TimeoutError:
                return _unverified(item, "The scan timed out, so this target is not verified as safe.")
            except BlockedTarget as e:
                return _unverified(item, f"Skipped: {e}")
            except Exception:
                logger.exception("Batch item failed")
                return _unverified(item, "The scan failed, so this target is not verified as safe.")

            triggers = list(getattr(risk_assessment, "triggers", []) or [])
            summary = _batch_summary(flagged, triggers)

            # Open a DB session only for the write, never during the slow network scan
            db_session = SessionLocal()
            try:
                _save(
                    db_session, owner_id,
                    modality="url" if request.scan_type == "url" else "text",
                    target=item,
                    severity_level=risk_assessment.level,
                    composite_risk_score=risk_assessment.score,
                    heuristic_score=float(risk_assessment.score),
                    ml_probability=ml_prob,
                    intel_feed_hits=1 if flagged else 0,
                    ai_explanation=summary,
                    evidence_json=evidence.model_dump() if hasattr(evidence, "model_dump") else {},
                )
            finally:
                db_session.close()

            return BatchScanItemResult(
                target=item,
                risk_score=risk_assessment.score,
                risk_level=risk_assessment.level,
                flags_count=len(triggers),
                summary=summary,
                threat_intel_flagged=flagged,
            )

    results = await asyncio.gather(*(process_single_item(i) for i in cleaned_items))

    # Highest risk first; unverified items come right after the scored ones
    results = sorted(results, key=lambda r: (r.risk_level == "UNKNOWN", -r.risk_score))

    return BatchScanResponse(
        total_items=len(results),
        high_risk_count=sum(1 for r in results if r.risk_level in ("HIGH", "CRITICAL")),
        medium_risk_count=sum(1 for r in results if r.risk_level == "MEDIUM"),
        low_risk_count=sum(1 for r in results if r.risk_level == "LOW"),
        results=results,
    )


# --------------------------------------------------------------------------- #
# PDF export
# --------------------------------------------------------------------------- #
@router.post("/export/pdf", dependencies=[Depends(read_limiter)])
async def export_pdf(scan_data: dict, http_request: Request):
    """Export scan results as a downloadable PDF report."""
    try:
        size = int(http_request.headers.get("content-length") or 0)
    except ValueError:
        size = 0
    if size > MAX_EXPORT_BYTES:
        raise HTTPException(status_code=413, detail="That report is too large to export.")
    try:
        pdf_bytes = await asyncio.to_thread(ReportGenerator.generate_pdf, scan_data)
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": "attachment; filename=cyberguardian_threat_report.pdf"},
        )
    except Exception:
        logger.exception("PDF export failed")
        raise HTTPException(status_code=500, detail="Could not generate the PDF report.")

# TEMPORARY: delete after checking the proxy headers
@router.get("/_debug/ip")
def debug_ip(request: Request):
    return {
        "client_host": request.client.host if request.client else None,
        "x_forwarded_for": request.headers.get("x-forwarded-for"),
        "cf_connecting_ip": request.headers.get("cf-connecting-ip"),
        "true_client_ip": request.headers.get("true-client-ip"),
    }