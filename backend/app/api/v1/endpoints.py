from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException, UploadFile, File, Depends
from sqlalchemy.orm import Session
import inspect
from app.models.schemas import (
    URLScanRequest,
    URLScanResponse,
    QRScanResponse,
    MessageScanRequest,
    MessageScanResponse,
    HistoryResponse,
)
from app.models.database import get_db, ScanAuditLog
from app.analyzers.url_analyzer import analyze_url
from app.analyzers.qr_analyzer import analyze_qr_code
from app.analyzers.text_analyzer import analyze_message_text
from app.services.risk_engine import (
    calculate_url_risk,
    calculate_qr_risk,
    calculate_message_risk,
)
from app.services.ai_explainer import AIExplainer

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

        latest_scans = all_scans[:20]

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