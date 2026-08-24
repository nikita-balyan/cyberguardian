import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.services.report_generator import ReportGenerator

client = TestClient(app)


@pytest.fixture
def sample_url_scan_data():
    return {
        "url": "https://paypal-security-update.suspicious-domain.com/login",
        "scan_type": "URL Scan",
        "risk_assessment": {
            "score": 88,
            "level": "CRITICAL",
            "triggers": [
                "suspicious_tld",
                "brand_impersonation",
                "recent_domain_creation",
            ],
        },
        "explanation": {
            "summary": "High-risk phishing target impersonating PayPal.",
            "why_flagged": [
                "Domain created 2 days ago.",
                "Impersonates trusted brand PayPal.",
                "Uses suspicious top-level domain.",
            ],
            "recommended_actions": [
                "Do not enter credentials or personal details.",
                "Report domain to hosting provider.",
            ],
            "educational_tip": "Always check the domain name in the browser address bar before entering passwords.",
        },
        "evidence": {
            "domain_age_days": 2,
            "ssl_valid": False,
            "ssl_issuer": None,
            "redirect_count": 2,
            "final_url": "https://paypal-security-update.suspicious-domain.com/login",
            "is_ip_address": False,
            "suspicious_tld": True,
            "brand_impersonation": True,
            "safe_browsing_hit": True,
        },
    }


@pytest.fixture
def sample_message_scan_data():
    return {
        "message": "URGENT: Your Netflix account has been suspended. Verify payment at http://netflix-update.xyz immediately.",
        "scan_type": "Phishing Message Scan",
        "risk_assessment": {
            "score": 75,
            "level": "HIGH",
            "triggers": ["urgency_language", "financial_lure", "suspicious_url"],
        },
        "explanation": {
            "summary": "Urgent SMS phishing message attempting credential theft.",
            "why_flagged": [
                "Contains high urgency language ('URGENT', 'immediately').",
                "Contains financial lure referencing account suspension.",
            ],
            "recommended_actions": [
                "Do not click the embedded link.",
                "Check account status via official app.",
            ],
            "educational_tip": "Legitimate services rarely demand immediate action via unverified SMS links.",
        },
        "evidence": {
            "urgency_detected": True,
            "financial_lures_detected": True,
            "suspicious_phone_or_sender": False,
            "extracted_urls": ["http://netflix-update.xyz"],
            "url_evidences": [],
        },
    }


def test_generate_pdf_service(sample_url_scan_data, sample_message_scan_data):
    # Test URL scan report generation
    pdf_bytes_url = ReportGenerator.generate_pdf(sample_url_scan_data)
    assert isinstance(pdf_bytes_url, bytes)
    assert len(pdf_bytes_url) > 0
    assert pdf_bytes_url.startswith(b"%PDF")

    # Test Message scan report generation
    pdf_bytes_msg = ReportGenerator.generate_pdf(sample_message_scan_data)
    assert isinstance(pdf_bytes_msg, bytes)
    assert len(pdf_bytes_msg) > 0
    assert pdf_bytes_msg.startswith(b"%PDF")


def test_export_pdf_endpoint(sample_url_scan_data):
    response = client.post("/api/v1/export/pdf", json=sample_url_scan_data)
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/pdf"
    assert "attachment; filename=cyberguardian_threat_report.pdf" in response.headers.get(
        "content-disposition", ""
    )
    assert len(response.content) > 0
    assert response.content.startswith(b"%PDF")


def test_export_pdf_endpoint_minimal_payload():
    response = client.post("/api/v1/export/pdf", json={"target": "https://clean-example.com"})
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/pdf"
    assert len(response.content) > 0
    assert response.content.startswith(b"%PDF")
