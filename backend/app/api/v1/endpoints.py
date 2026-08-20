from fastapi import APIRouter, HTTPException, UploadFile, File
import inspect
from app.models.schemas import (
    URLScanRequest,
    URLScanResponse,
    QRScanResponse,
    MessageScanRequest,
    MessageScanResponse,
)
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
async def scan_url(request: URLScanRequest):
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
async def scan_qr(file: UploadFile = File(...)):
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
async def scan_message(request: MessageScanRequest):
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