import asyncio
import pytest
from unittest.mock import patch, MagicMock
from backend.app.services.threat_intel import ThreatIntelService

def test_threat_intel_benign():
    async def run_test():
        service = ThreatIntelService()
        
        # Mock URLhaus response (no results)
        mock_urlhaus_response = MagicMock()
        mock_urlhaus_response.status_code = 200
        mock_urlhaus_response.json.return_value = {"query_status": "no_results"}
        
        # Mock GSB response (clean)
        mock_gsb_response = MagicMock()
        mock_gsb_response.status_code = 200
        mock_gsb_response.json.return_value = {}
        
        with patch('httpx.AsyncClient.post', side_effect=[mock_urlhaus_response, mock_gsb_response]):
            result = await service.lookup("https://example.com")
            assert result["flagged"] is False
            assert len(result["threat_summary"]) == 0
            assert result["sources"]["urlhaus"]["flagged"] is False
            assert result["sources"]["google_safebrowsing"]["flagged"] is False

    asyncio.run(run_test())

def test_threat_intel_flagged_urlhaus():
    async def run_test():
        service = ThreatIntelService()
        
        mock_urlhaus_response = MagicMock()
        mock_urlhaus_response.status_code = 200
        mock_urlhaus_response.json.return_value = {
            "query_status": "ok",
            "threat": "malware_download",
            "tags": ["payload", "exe"],
            "urlhaus_reference": "https://urlhaus.abuse.ch/url/12345/"
        }
        
        mock_gsb_response = MagicMock()
        mock_gsb_response.status_code = 200
        mock_gsb_response.json.return_value = {}
        
        with patch('httpx.AsyncClient.post', side_effect=[mock_urlhaus_response, mock_gsb_response]):
            result = await service.lookup("https://malicious-executable.com")
            assert result["flagged"] is True
            assert len(result["threat_summary"]) > 0
            assert result["sources"]["urlhaus"]["flagged"] is True
            assert "URLhaus" in result["threat_summary"][0]

    asyncio.run(run_test())


