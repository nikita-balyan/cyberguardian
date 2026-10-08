import pytest
from backend.app.models.schemas import URLEvidence
from backend.app.services.risk_engine import calculate_url_risk

def test_clean_url_risk():
    evidence = URLEvidence(
        domain_age_days=500,
        ssl_valid=True,
        ssl_issuer="DigiCert",
        redirect_count=1,
        final_url="https://example.com",
        is_ip_address=False,
        suspicious_tld=False,
        brand_impersonation=False,
        safe_browsing_hit=False,
        ml_probability=0.0
    )
    assessment = calculate_url_risk(evidence)
    assert assessment.score == 0
    assert assessment.level == 'LOW'
    assert len(assessment.triggers) == 0

def test_malicious_safe_browsing_override():
    evidence = URLEvidence(
        domain_age_days=100,
        ssl_valid=True,
        ssl_issuer="Let's Encrypt",
        redirect_count=0,
        final_url="https://malicious.com",
        is_ip_address=False,
        suspicious_tld=False,
        brand_impersonation=False,
        safe_browsing_hit=True,
        ml_probability=0.0
    )
    assessment = calculate_url_risk(evidence)
    assert assessment.score >= 95
    assert assessment.level == 'CRITICAL'
    assert any("Safe Browsing" in t for t in assessment.triggers)

def test_risk_scoring_accumulations():
    evidence = URLEvidence(
        domain_age_days=5, # +25 pts
        ssl_valid=False, # +15 pts
        ssl_issuer=None,
        redirect_count=3, # +15 pts
        final_url="http://192.168.1.1/sbi-login.xyz",
        is_ip_address=True, # +20 pts
        suspicious_tld=True, # +10 pts
        brand_impersonation=True, # +25 pts
        safe_browsing_hit=False,
        ml_probability=0.0
    )
    # Cat 2 (Age < 14): 25
    # Cat 3 (Brand): 25
    # Independent: SSL (15) + TLD (10) + IP (20) + Redirects (15) = 60
    # Total heuristic = 25 + 25 + 60 = 110 -> clamped to 100
    # Composite = 0.4*100 + 0.4*0 + 0.2*0 = 40
    assessment = calculate_url_risk(evidence)
    assert assessment.score == 40
    assert assessment.level == 'MEDIUM'
    assert len(assessment.triggers) >= 5
