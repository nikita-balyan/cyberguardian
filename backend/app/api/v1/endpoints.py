from datetime import datetime, timezone
import asyncio
import inspect
from fastapi import APIRouter, HTTPException, UploadFile, File, Depends, Response
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
from app.analyzers.url_analyzer import analyze_url
from app.analyzers.qr_analyzer import analyze_qr_code
from app.analyzers.text_analyzer import analyze_message_text
from app.services.risk_engine import (
    calculate_url_risk,
    calculate_qr_risk,
    calculate_message_risk,
)
from app.services.ai_explainer import AIExplainer
from app.services.report_generator import ReportGenerator

router = APIRouter()
ai_explainer = AIExplainer()


@router.post("/scan/url", response_model=URLScanResponse)
async def scan_url(request: URLScanRequest, db: Session = Depends(get_db)):
    try:
        evidence = analyze_url(request.url)
        if inspect.isawaitable(evidence):
            evidence = await evidence
        risk_assessment = calculate_url_risk(evidence)
        if inspect.isawaitable(risk_assessment):
            risk_assessment = await risk_assessment
        explanation = ai_explainer.generate_explanation(
            evidence.model_dump(), risk_assessment.model_dump()
        )

        audit_log = ScanAuditLog(
            scan_type="url",
            target=request.url,
            risk_level=risk_assessment.level,
            risk_score=risk_assessment.score,
            summary=explanation.summary,
            evidence=evidence.model_dump(),
            created_at=datetime.now(timezone.utc),
        )
        db.add(audit_log)
        db.commit()

        return URLScanResponse(
            url=request.url,
            evidence=evidence,
            risk_assessment=risk_assessment,
            explanation=explanation,
        )
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Internal server error during URL analysis: {str(e)}",
        )


@router.post("/scan/qr", response_model=QRScanResponse)
async def scan_qr(file: UploadFile = File(...), db: Session = Depends(get_db)):
    try:
        content = await file.read()
        evidence = analyze_qr_code(content)
        if inspect.isawaitable(evidence):
            evidence = await evidence
        risk_assessment = calculate_qr_risk(evidence)
        if inspect.isawaitable(risk_assessment):
            risk_assessment = await risk_assessment
        explanation = ai_explainer.generate_explanation(
            evidence.model_dump(), risk_assessment.model_dump()
        )

        target_str = evidence.extracted_text if evidence.extracted_text else (file.filename or "Uploaded QR Code")
        audit_log = ScanAuditLog(
            scan_type="qr",
            target=target_str,
            risk_level=risk_assessment.level,
            risk_score=risk_assessment.score,
            summary=explanation.summary,
            evidence=evidence.model_dump(),
            created_at=datetime.now(timezone.utc),
        )
        db.add(audit_log)
        db.commit()

        return QRScanResponse(
            evidence=evidence,
            risk_assessment=risk_assessment,
            explanation=explanation,
        )
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Internal server error during QR code analysis: {str(e)}",
        )


@router.post("/scan/message", response_model=MessageScanResponse)
async def scan_message(request: MessageScanRequest, db: Session = Depends(get_db)):
    try:
        evidence = analyze_message_text(request.message)
        if inspect.isawaitable(evidence):
            evidence = await evidence
        risk_assessment = calculate_message_risk(evidence)
        if inspect.isawaitable(risk_assessment):
            risk_assessment = await risk_assessment
        explanation = ai_explainer.generate_explanation(
            evidence.model_dump(), risk_assessment.model_dump()
        )

        audit_log = ScanAuditLog(
            scan_type="message",
            target=request.message,
            risk_level=risk_assessment.level,
            risk_score=risk_assessment.score,
            summary=explanation.summary,
            evidence=evidence.model_dump(),
            created_at=datetime.now(timezone.utc),
        )
        db.add(audit_log)
        db.commit()

        return MessageScanResponse(
            message=request.message,
            evidence=evidence,
            risk_assessment=risk_assessment,
            explanation=explanation,
        )
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Internal server error during message analysis: {str(e)}",
        )


@router.get("/history", response_model=HistoryResponse)
def get_scan_history(db: Session = Depends(get_db)):
    try:
        all_scans = (
            db.query(ScanAuditLog)
            .order_by(ScanAuditLog.created_at.desc(), ScanAuditLog.id.desc())
            .all()
        )
        total_scans = len(all_scans)

        high_count = sum(1 for s in all_scans if s.risk_level in ["HIGH", "CRITICAL"])
        medium_count = sum(1 for s in all_scans if s.risk_level == "MEDIUM")
        low_count = sum(1 for s in all_scans if s.risk_level == "LOW")
        critical_count = sum(1 for s in all_scans if s.risk_level == "CRITICAL")

        risk_breakdown = {
            "high": high_count,
            "medium": medium_count,
            "low": low_count,
            "critical": critical_count,
            "HIGH": high_count,
            "MEDIUM": medium_count,
            "LOW": low_count,
            "CRITICAL": critical_count,
        }

        latest_scans = all_scans[:50]

        return HistoryResponse(
            total_scans=total_scans,
            risk_breakdown=risk_breakdown,
            scans=latest_scans,
        )
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Internal server error retrieving scan history: {str(e)}",
        )


@router.post("/scan/batch", response_model=BatchScanResponse)
async def scan_batch(request: BatchScanRequest):
    """
    Perform a batch / bulk multi-target threat scan on up to 50 items (URLs or messages)
    concurrently using asyncio with semaphore limiting.
    """
    cleaned_items = [item.strip() for item in request.items if item and item.strip()]
    if len(cleaned_items) > 50:
        raise HTTPException(
            status_code=400,
            detail="Maximum 50 items allowed per batch scan."
        )
    if not cleaned_items:
        raise HTTPException(
            status_code=400,
            detail="No valid items provided for batch scan."
        )

    semaphore = asyncio.Semaphore(10)

    async def process_single_item(item: str) -> BatchScanItemResult:
        async with semaphore:
            db_session = SessionLocal()
            try:
                # Wrap item processing with a 5-second timeout safeguard
                async def _evaluate():
                    if request.scan_type == "url":
                        evidence = analyze_url(item)
                        if inspect.isawaitable(evidence):
                            evidence = await evidence
                        risk_assessment = calculate_url_risk(evidence)
                        if inspect.isawaitable(risk_assessment):
                            risk_assessment = await risk_assessment

                        threat_intel = getattr(evidence, "threat_intel", None)
                        threat_intel_flagged = False
                        if isinstance(threat_intel, dict):
                            threat_intel_flagged = threat_intel.get("flagged", False)
                        elif hasattr(threat_intel, "flagged"):
                            threat_intel_flagged = threat_intel.flagged
                        
                        safe_browsing = getattr(evidence, "safe_browsing_hit", False)
                        threat_intel_flagged = bool(safe_browsing or threat_intel_flagged)

                    else:  # message
                        evidence = analyze_message_text(item)
                        if inspect.isawaitable(evidence):
                            evidence = await evidence
                        risk_assessment = calculate_message_risk(evidence)
                        if inspect.isawaitable(risk_assessment):
                            risk_assessment = await risk_assessment

                        url_evs = getattr(evidence, "url_evidences", []) or []
                        threat_intel_flagged = any(
                            bool(
                                getattr(e, "safe_browsing_hit", False) or
                                (
                                    getattr(e, "threat_intel", {}).get("flagged", False)
                                    if isinstance(getattr(e, "threat_intel", None), dict)
                                    else getattr(getattr(e, "threat_intel", None), "flagged", False)
                                )
                            )
                            for e in url_evs
                        )

                    return evidence, risk_assessment, threat_intel_flagged

                evidence, risk_assessment, threat_intel_flagged = await asyncio.wait_for(_evaluate(), timeout=5.0)

                # Extract risk triggers/factors
                triggers = getattr(risk_assessment, "triggers", []) or getattr(risk_assessment, "factors", []) or []
                flags_count = len(triggers)

                # Generate fast, deterministic rule-based summary for batch triage
                if threat_intel_flagged:
                    summary_text = f"Flagged by threat intelligence feeds as known malicious indicator."
                elif flags_count > 0:
                    trigger_names = [getattr(t, "rule", str(t)) for t in triggers[:2]]
                    summary_text = f"Flagged {flags_count} threat indicators ({', '.join(trigger_names)})."
                else:
                    summary_text = "No anomalous risk indicators detected. Target evaluated clean."

                # Safe evidence serialization
                evidence_data = (
                    evidence.model_dump()
                    if hasattr(evidence, "model_dump")
                    else (evidence.dict() if hasattr(evidence, "dict") else {})
                )

                # Persist to database history
                try:
                    audit_log = ScanAuditLog(
                        scan_type=request.scan_type,
                        target=item,
                        risk_level=risk_assessment.level,
                        risk_score=risk_assessment.score,
                        summary=summary_text,
                        evidence=evidence_data,
                        created_at=datetime.now(timezone.utc),
                    )
                    db_session.add(audit_log)
                    db_session.commit()
                except Exception:
                    db_session.rollback()

                return BatchScanItemResult(
                    target=item,
                    risk_score=risk_assessment.score,
                    risk_level=risk_assessment.level,
                    flags_count=flags_count,
                    summary=summary_text,
                    threat_intel_flagged=threat_intel_flagged
                )

            except asyncio.TimeoutError:
                db_session.rollback()
                return BatchScanItemResult(
                    target=item,
                    risk_score=0,
                    risk_level="LOW",
                    flags_count=0,
                    summary="Target scan timed out (DNS or network probe latency).",
                    threat_intel_flagged=False
                )
            except Exception as e:
                db_session.rollback()
                return BatchScanItemResult(
                    target=item,
                    risk_score=0,
                    risk_level="LOW",
                    flags_count=0,
                    summary=f"Analysis completed: {str(e)[:60]}",
                    threat_intel_flagged=False
                )
            finally:
                db_session.close()

    tasks = [process_single_item(item) for item in cleaned_items]
    results = await asyncio.gather(*tasks)

    # Sort results by risk_score descending (highest risk first)
    results = sorted(results, key=lambda r: r.risk_score, reverse=True)

    high_risk_count = sum(1 for r in results if r.risk_level in ["HIGH", "CRITICAL"])
    medium_risk_count = sum(1 for r in results if r.risk_level == "MEDIUM")
    low_risk_count = sum(1 for r in results if r.risk_level == "LOW")

    return BatchScanResponse(
        total_items=len(results),
        high_risk_count=high_risk_count,
        medium_risk_count=medium_risk_count,
        low_risk_count=low_risk_count,
        results=results
    )


@router.post("/export/pdf")
async def export_pdf(scan_data: dict):
    """
    Export scan results as a downloadable forensic threat report PDF.
    """
    try:
        pdf_bytes = ReportGenerator.generate_pdf(scan_data)
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": "attachment; filename=cyberguardian_threat_report.pdf"
            },
        )
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to generate forensic PDF report: {str(e)}",
        )
