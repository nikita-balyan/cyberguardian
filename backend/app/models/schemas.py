from datetime import datetime
from pydantic import BaseModel, ConfigDict
from typing import List, Optional
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

    id: int
    scan_type: str
    target: str
    risk_level: str
    risk_score: int
    summary: Optional[str] = None
    evidence: dict
    created_at: datetime

class HistoryResponse(BaseModel):
    total_scans: int
    risk_breakdown: dict
    scans: List[ScanAuditLogResponse]


