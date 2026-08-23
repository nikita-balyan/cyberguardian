import os
import logging
import httpx
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)

class ThreatIntelService:
    def __init__(self):
        self.google_api_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "")

    async def check_urlhaus(self, url: str) -> Dict[str, Any]:
        """
        Query URLhaus public API (https://urlhaus-api.abuse.ch/v1/url/).
        POST request with form data: {"url": url}.
        Flag if query_status == "ok".
        """
        endpoint = "https://urlhaus-api.abuse.ch/v1/url/"
        result = {
            "queried": True,
            "flagged": False,
            "status": "error",
            "threat": None,
            "tags": None,
            "urlhaus_reference": None
        }
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.post(endpoint, data={"url": url})
                if response.status_code == 200:
                    data = response.json()
                    query_status = data.get("query_status")
                    result["status"] = query_status
                    if query_status == "ok":
                        result["flagged"] = True
                        result["threat"] = data.get("threat")
                        result["tags"] = data.get("tags")
                        result["urlhaus_reference"] = data.get("urlhaus_reference")
                    elif query_status in ["no_results", "invalid_url", "skipped"]:
                        result["flagged"] = False
                    else:
                        result["flagged"] = False
                else:
                    result["status"] = f"http_{response.status_code}"
                    logger.warning(f"URLhaus API returned status code {response.status_code}")
        except Exception as e:
            logger.warning(f"Error querying URLhaus API: {e}")
            result["status"] = "exception"
        return result

    async def check_google_safebrowsing(self, url: str) -> Dict[str, Any]:
        """
        Query Google Safe Browsing API v4.
        Gracefully mark unconfigured if GOOGLE_SAFE_BROWSING_API_KEY is absent.
        """
        result = {
            "queried": False,
            "flagged": False,
            "status": "unconfigured",
            "matches": []
        }
        if not self.google_api_key:
            logger.warning("GOOGLE_SAFE_BROWSING_API_KEY is not configured. Skipping Safe Browsing check.")
            return result

        result["queried"] = True
        result["status"] = "configured"
        api_endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={self.google_api_key}"
        payload = {
            "client": {
                "clientId": "cyberguardian",
                "clientVersion": "1.0.0"
            },
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION"
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [
                    {"url": url}
                ]
            }
        }

        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.post(api_endpoint, json=payload)
                if response.status_code == 200:
                    data = response.json()
                    if data and "matches" in data and len(data["matches"]) > 0:
                        result["flagged"] = True
                        result["status"] = "match_found"
                        result["matches"] = data["matches"]
                    else:
                        result["flagged"] = False
                        result["status"] = "clean"
                else:
                    result["status"] = f"http_{response.status_code}"
                    logger.warning(f"Google Safe Browsing API returned status code {response.status_code}: {response.text}")
        except Exception as e:
            logger.warning(f"Error querying Google Safe Browsing API: {e}")
            result["status"] = "exception"

        return result

    async def lookup(self, url: str) -> Dict[str, Any]:
        """
        Aggregating results from URLhaus and Google Safe Browsing,
        setting flagged: bool, threat_summary: list[str], and structured source details.
        """
        urlhaus_res = await self.check_urlhaus(url)
        gsb_res = await self.check_google_safebrowsing(url)

        flagged = urlhaus_res.get("flagged", False) or gsb_res.get("flagged", False)
        threat_summary = []

        if urlhaus_res.get("flagged"):
            threat = urlhaus_res.get("threat") or "malicious"
            tags = urlhaus_res.get("tags")
            tag_str = f" (Tags: {', '.join(tags)})" if tags else ""
            threat_summary.append(f"URLhaus flagged this URL as threat: {threat}{tag_str}")

        if gsb_res.get("flagged"):
            matches = gsb_res.get("matches", [])
            threat_types = [m.get("threatType", "threat") for m in matches]
            threat_summary.append(f"Google Safe Browsing flagged this URL (Threat Types: {', '.join(threat_types)})")

        return {
            "flagged": flagged,
            "threat_summary": threat_summary,
            "sources": {
                "urlhaus": urlhaus_res,
                "google_safebrowsing": gsb_res
            }
        }

# For backward compatibility
async def check_safe_browsing(url: str) -> bool:
    service = ThreatIntelService()
    res = await service.check_google_safebrowsing(url)
    return res.get("flagged", False)
