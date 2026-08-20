from pydantic import BaseModel
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

class RiskAssessment(BaseModel):
    score: int
    level: str
    triggers: List[str]

class URLScanResponse(BaseModel):
    url: str
    evidence: URLEvidence
    risk_assessment: RiskAssessment
    explanation: AIExplanation
