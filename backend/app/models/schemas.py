#schemas.py
from datetime import datetime
from uuid import UUID
from typing import List, Optional, Union
from pydantic import BaseModel, ConfigDict
from app.services.ai_explainer import AIExplanation


class URLScanRequest(BaseModel):
    url: str

class URLEvidence(BaseModel):
    domain_age_days: Optional[int] = None
    ssl_valid: bool = False
    ssl_issuer: Optional[str] = None
    redirect_count: int = 0
    final_url: str
    is_ip_address: bool = False
    suspicious_tld: bool = False
    brand_impersonation: bool = False
    safe_browsing_hit: bool = False
    threat_intel: Optional[dict] = None
    ml_probability: Optional[float] = None
    lexical_features: Optional[dict] = None

class RiskAssessment(BaseModel):
    score: int
    level: str
    triggers: List[str]

class URLScanResponse(BaseModel):
    url: str
    evidence: URLEvidence
    risk_assessment: RiskAssessment
    explanation: AIExplanation

class QREvidence(BaseModel):
    has_qr_code: bool
    extracted_text: Optional[str] = None
    is_url: bool = False
    url_evidence: Optional[URLEvidence] = None

class QRScanResponse(BaseModel):
    evidence: QREvidence
    risk_assessment: RiskAssessment
    explanation: AIExplanation

class MessageEvidence(BaseModel):
    urgency_detected: bool
    financial_lures_detected: bool
    suspicious_phone_or_sender: bool
    extracted_urls: List[str]
    url_evidences: List[URLEvidence]

class MessageScanRequest(BaseModel):
    message: str

class MessageScanResponse(BaseModel):
    message: str
    evidence: MessageEvidence
    risk_assessment: RiskAssessment
    explanation: AIExplanation

class ScanAuditLogResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: Optional[Union[int, UUID, str]] = None
    scan_type: Optional[str] = None
    modality: Optional[str] = None
    target: str
    risk_level: Optional[str] = None
    severity_level: Optional[str] = None
    risk_score: Optional[int] = None
    composite_risk_score: Optional[int] = None
    heuristic_score: Optional[float] = None
    ml_probability: Optional[float] = None
    summary: Optional[str] = None
    ai_explanation: Optional[str] = None
    evidence: Optional[dict] = None
    evidence_json: Optional[dict] = None
    created_at: datetime


class BatchScanRequest(BaseModel):
    items: List[str]
    scan_type: str = "url"  # "url" | "message"

class BatchScanItemResult(BaseModel):
    target: str
    risk_score: int
    risk_level: str
    flags_count: int
    summary: str
    threat_intel_flagged: bool

class BatchScanResponse(BaseModel):
    total_items: int
    high_risk_count: int
    medium_risk_count: int
    low_risk_count: int
    results: List[BatchScanItemResult]

class HistoryResponse(BaseModel):
    total_scans: int
    risk_breakdown: dict
    scans: List[ScanAuditLogResponse]



