import pytest
from unittest.mock import MagicMock, patch
from backend.app.services.ai_explainer import AIExplainer, AIExplanation
from backend.app.models.schemas import URLEvidence, RiskAssessment

@pytest.fixture
def mock_gemini_api():
    with patch('google.generativeai.GenerativeModel') as mock_model:
        mock_instance = MagicMock()
        mock_model.return_value = mock_instance
        yield mock_instance

def test_ai_explainer_initialization_without_api_key():
    with patch('backend.app.services.ai_explainer.GEMINI_API_KEY', None):
        explainer = AIExplainer()
        assert explainer.model is None

def test_ai_explainer_initialization_with_api_key(mock_gemini_api):
    with patch('backend.app.services.ai_explainer.GEMINI_API_KEY', 'test_key'):
        explainer = AIExplainer()
        assert explainer.model is not None

def test_generate_explanation_success(mock_gemini_api):
    with patch('backend.app.services.ai_explainer.GEMINI_API_KEY', 'test_key'):
        explainer = AIExplainer()
        
        # Mock response text
        mock_gemini_api.generate_content.return_value.text = """
        {
            "summary": "This is a successful AI summary.",
            "why": ["The domain was flagged.", "Invalid SSL certificate."],
            "what_to_do": ["Do not enter credentials."],
            "educational_tip": "Check the address bar."
        }
        """
        
        evidence = URLEvidence(
            final_url="https://malicious-site.com",
            ssl_valid=False,
            redirect_count=1
        )
        risk_assessment = RiskAssessment(
            score=75,
            level="HIGH",
            triggers=["invalid_ssl"]
        )
        
        explanation = explainer.generate_explanation(evidence.model_dump(), risk_assessment.model_dump())
        
        assert isinstance(explanation, AIExplanation)
        assert explanation.summary == "This is a successful AI summary."
        assert "The domain was flagged." in explanation.why
        assert "Do not enter credentials." in explanation.what_to_do
        assert explanation.educational_tip == "Check the address bar."
        mock_gemini_api.generate_content.assert_called_once()

def test_generate_explanation_api_failure_fallback(mock_gemini_api):
    with patch('backend.app.services.ai_explainer.GEMINI_API_KEY', 'test_key'):
        explainer = AIExplainer()
        mock_gemini_api.generate_content.side_effect = Exception("API connection timed out")
        
        evidence = URLEvidence(
            final_url="https://malicious-site.com",
            ssl_valid=False,
            redirect_count=1,
            brand_impersonation=True
        )
        risk_assessment = RiskAssessment(
            score=90,
            level="CRITICAL",
            triggers=["invalid_ssl", "brand_impersonation"]
        )
        
        explanation = explainer.generate_explanation(evidence.model_dump(), risk_assessment.model_dump())
        
        assert isinstance(explanation, AIExplanation)
        assert explanation.summary == "A default explanation was generated due to an issue with the AI service."
        assert "Risk score: 90" in explanation.why
        assert "Severity: CRITICAL" in explanation.why
        assert "The SSL certificate for the website is invalid or expired." in explanation.why
        assert "The URL looks like an impersonation of a trusted brand." in explanation.why
        assert "Do not enter passwords or sensitive information." in explanation.what_to_do

def test_generate_explanation_no_api_key_fallback():
    with patch('backend.app.services.ai_explainer.GEMINI_API_KEY', None):
        explainer = AIExplainer()
        assert explainer.model is None
        
        evidence = URLEvidence(
            final_url="https://malicious-site.com",
            ssl_valid=False,
            redirect_count=1,
            brand_impersonation=True
        )
        risk_assessment = RiskAssessment(
            score=90,
            level="CRITICAL",
            triggers=["invalid_ssl", "brand_impersonation"]
        )
        
        explanation = explainer.generate_explanation(evidence.model_dump(), risk_assessment.model_dump())
        
        assert isinstance(explanation, AIExplanation)
        assert explanation.summary == "Analyzed risk level is CRITICAL with a score of 90/100."
        assert "Risk score: 90" in explanation.why
        assert "Severity: CRITICAL" in explanation.why
        assert "The SSL certificate for the website is invalid or expired." in explanation.why
        assert "The URL looks like an impersonation of a trusted brand." in explanation.why
        assert "Do not enter passwords or sensitive information." in explanation.what_to_do
