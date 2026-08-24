import os
import logging
import httpx
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)

class ThreatIntelService:
    def __init__(self):
        self.google_api_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "")
        self.urlhaus_api_key = os.getenv("URLHAUS_API_KEY", "")

    async def check_urlhaus(self, url: str) -> Dict[str, Any]:
        """
        Query URLhaus public API (https://urlhaus-api.abuse.ch/v1/url/).
        POST request with form data: {"url": url}.
        Gracefully handles 401s, 403s, and timeouts without crashing callers.
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

        headers = {}
        if self.urlhaus_api_key:
            headers["Auth-Key"] = self.urlhaus_api_key

        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                response = await client.post(endpoint, data={"url": url}, headers=headers)
                if response.status_code == 200:
                    data = response.json()
                    query_status = data.get("query_status")
                    result["status"] = query_status
                    if query_status == "ok":
                        result["flagged"] = True
                        result["threat"] = data.get("threat")
                        result["tags"] = data.get("tags")
                        result["urlhaus_reference"] = data.get("urlhaus_reference")
                    else:
                        result["flagged"] = False
                elif response.status_code in [401, 403]:
                    # Unauthenticated or rate-limited URLhaus endpoint; log debug and treat as unflagged
                    logger.debug(f"URLhaus API returned {response.status_code}. Skipping feed.")
                    result["status"] = "unauthenticated"
                    result["flagged"] = False
                else:
                    result["status"] = f"http_{response.status_code}"
                    result["flagged"] = False
        except Exception as e:
            logger.debug(f"URLhaus query error: {e}")
            result["status"] = "exception"
            result["flagged"] = False

        return result

    async def check_google_safebrowsing(self, url: str) -> Dict[str, Any]:
        """
        Query Google Safe Browsing API v4.
        Gracefully marks unconfigured if GOOGLE_SAFE_BROWSING_API_KEY is absent.
        """
        result = {
            "queried": False,
            "flagged": False,
            "status": "unconfigured",
            "matches": []
        }
        if not self.google_api_key:
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
            async with httpx.AsyncClient(timeout=3.0) as client:
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
                    result["flagged"] = False
        except Exception as e:
            logger.debug(f"Google Safe Browsing error: {e}")
            result["status"] = "exception"
            result["flagged"] = False

        return result

    async def lookup(self, url: str) -> Dict[str, Any]:
        """
        Aggregate results from URLhaus and Google Safe Browsing.
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
