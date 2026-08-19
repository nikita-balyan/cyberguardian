import logging
import httpx
from ..config import GOOGLE_SAFE_BROWSING_API_KEY

logger = logging.getLogger(__name__)

async def check_safe_browsing(url: str) -> bool:
    """
    Query Google Safe Browsing API v4 to check if a URL is malicious.
    Gracefully degrades to False if API key is missing or request fails/times out.
    """
    if not GOOGLE_SAFE_BROWSING_API_KEY:
        logger.warning("GOOGLE_SAFE_BROWSING_API_KEY is not configured. Skipping Safe Browsing check.")
        return False

    api_endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_BROWSING_API_KEY}"
    
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
                # If matches are found, 'matches' key will be present and non-empty
                if data and "matches" in data and len(data["matches"]) > 0:
                    return True
            else:
                logger.warning(f"Google Safe Browsing API returned status code {response.status_code}: {response.text}")
    except Exception as e:
        logger.warning(f"Error querying Google Safe Browsing API: {e}")

    return False
