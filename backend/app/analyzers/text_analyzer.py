import re
import logging
from typing import List, Optional

from ..models.schemas import MessageEvidence, URLEvidence
from .url_analyzer import analyze_url

logger = logging.getLogger(__name__)

# Heuristic lists for case-insensitive matching
URGENCY_TRIGGERS = [
    "account suspended",
    "act immediately",
    "unauthorized login",
    "urgent",
    "immediate action",
    "action required",
    "suspended immediately",
    "verify your account",
    "security alert",
    "unauthorized access",
    "expires in",
    "final notice",
    "unusual activity"
]

FINANCIAL_LURES = [
    "bank",
    "crypto",
    "refund",
    "wire",
    "password reset",
    "billing",
    "credit card",
    "payment",
    "invoice",
    "bitcoin",
    "ethereum",
    "wallet",
    "claim bonus",
    "cash prize",
    "lottery",
    "transfer",
    "unauthorized transaction"
]

# Regexes for suspicious senders or phone patterns
# e.g., emails/SMS mimicking official sources but looking spoofed/suspicious, or weird shortcodes
SUSPICIOUS_SENDER_REGEX = [
    r"(?i)\b(?:from|sender|reply-to)\s*:\s*[a-zA-Z0-9._%+-]+@(?:xyz|top|buzz|gq|ml|tk|cc)\b",  # Suspicious email TLD in Sender header
    r"(?i)\b(?:from|sender)\s*:\s*(?!support@|info@|no-reply@|noreply@)[a-zA-Z0-9._%+-]+@\b", # general sender checks
    r"(?i)\b(?:sms|caller|phone)\s*:\s*(?:\+?1?-?000-000-0000|000000|12345)\b", # obviously fake/suspicious numbers
    r"\b\+?[0-9]{5,6}\b", # SMS shortcodes (high risk of spoofing/phishing campaigns in bulk)
]

def extract_urls(text: str) -> List[str]:
    """
    Extracts all URLs from message text using regex and cleans up any trailing punctuation.
    """
    # Find URLs starting with http:// or https:// or www.
    url_pattern = r'\b(?:https?://|www\.)[a-zA-Z0-9.\-_~:/?#\[\]@!$&\'()*+,;=%]+'
    found = re.findall(url_pattern, text)
    
    # Clean up trailing punctuation often included in the regex match from standard text sentences
    cleaned_urls = []
    for url in found:
        # Strip trailing punctuation
        while url and url[-1] in [".", ",", ")", "]", "?", "!", ";", ":"]:
            url = url[:-1]
        if url not in cleaned_urls:
            cleaned_urls.append(url)
            
    return cleaned_urls

async def analyze_message_text(text: str) -> MessageEvidence:
    """
    Analyzes email/SMS message text for phishing cues and returns MessageEvidence.
    """
    text_lower = text.lower()
    
    # 1. Check Urgency / Pressure triggers
    urgency_detected = any(trigger in text_lower for trigger in URGENCY_TRIGGERS)
    
    # 2. Check Financial / Credential Lures
    financial_lures_detected = any(lure in text_lower for lure in FINANCIAL_LURES)
    
    # 3. Check Suspicious Senders/Phone Numbers
    suspicious_phone_or_sender = False
    for pattern in SUSPICIOUS_SENDER_REGEX:
        if re.search(pattern, text):
            suspicious_phone_or_sender = True
            break
            
    # Extra quick check: if the text mentions suspicious SMS-style codes or spoof headers
    if "sender:" in text_lower or "from:" in text_lower or "reply-to:" in text_lower:
        # Check if it has suspicious domains or mismatch
        if any(bad_tld in text_lower for bad_tld in [".xyz", ".top", ".buzz", ".tk", ".cc", ".gq"]):
            suspicious_phone_or_sender = True

    # 4. Extract embedded URLs
    extracted_urls = extract_urls(text)
    
    # 5. Route all extracted URLs to analyze_url()
    url_evidences: List[URLEvidence] = []
    for url in extracted_urls:
        try:
            # Normalize url for analyze_url
            url_to_analyze = url
            if url_to_analyze.startswith("www."):
                url_to_analyze = "https://" + url_to_analyze
            elif not url_to_analyze.startswith(("http://", "https://")):
                url_to_analyze = "https://" + url_to_analyze
            
            evidence = await analyze_url(url_to_analyze)
            url_evidences.append(evidence)
        except Exception as e:
            logger.error(f"Failed to analyze extracted URL '{url}': {e}")
            # Insert a basic/fallback evidence so the URL is still recognized
            url_evidences.append(URLEvidence(
                domain_age_days=None,
                ssl_valid=False,
                ssl_issuer=None,
                redirect_count=0,
                final_url=url,
                is_ip_address=False,
                suspicious_tld=any(url.endswith(tld) for tld in [".xyz", ".top", ".buzz", ".tk", ".cc", ".gq", ".ml"]),
                brand_impersonation=False,
                safe_browsing_hit=False,
                threat_intel=None
            ))

    return MessageEvidence(
        urgency_detected=urgency_detected,
        financial_lures_detected=financial_lures_detected,
        suspicious_phone_or_sender=suspicious_phone_or_sender,
        extracted_urls=extracted_urls,
        url_evidences=url_evidences
    )
