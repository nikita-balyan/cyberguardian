import asyncio
import ipaddress
import logging
import re
from typing import List
from urllib.parse import urlparse

from ..models.schemas import MessageEvidence, URLEvidence
from .url_analyzer import analyze_url, BlockedTarget

logger = logging.getLogger(__name__)

MAX_URLS_PER_MESSAGE = 10   # links beyond this are not scanned
URL_CONCURRENCY = 5
PER_URL_TIMEOUT = 25.0

SUSPICIOUS_URL_TLDS = (".xyz", ".top", ".buzz", ".tk", ".cc", ".gq", ".ml", ".ga", ".work", ".loan", ".click")

URGENCY_TRIGGERS = [
    "account suspended",
    "act immediately",
    "unauthorized login",
    "urgent",
    "urgently",
    "immediate action",
    "action required",
    "suspended immediately",
    "verify your account",
    "security alert",
    "unauthorized access",
    "expires in",
    "final notice",
    "unusual activity",
]

FINANCIAL_LURES = [
    "bank",
    "banking",
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
    "unauthorized transaction",
]


def _compile_terms(terms: List[str]) -> "re.Pattern":
    """Whole-word / whole-phrase match, with an optional plural 's'."""
    body = "|".join(re.escape(t) for t in terms)
    return re.compile(rf"\b(?:{body})s?\b", re.IGNORECASE)


URGENCY_RE = _compile_terms(URGENCY_TRIGGERS)
FINANCIAL_RE = _compile_terms(FINANCIAL_LURES)

_BAD_EMAIL_TLDS = r"(?:xyz|top|buzz|gq|ml|tk|cc|cf|ga|icu|click|loan|work|site|online)"

SUSPICIOUS_SENDER_PATTERNS = [
    # A sender header on a throwaway TLD, e.g. "From: PayPal <help@secure-mail.xyz>"
    re.compile(rf"\b(?:from|sender|reply-to)\s*:[^\n]*?@[a-z0-9.\-]+\.{_BAD_EMAIL_TLDS}\b", re.IGNORECASE),
    # Obviously fake numbers
    re.compile(r"\b(?:sms|caller|phone)\s*:\s*(?:\+?1?-?000-000-0000|000000|12345)\b", re.IGNORECASE),
]

_URL_RE = re.compile(r"\b(?:https?://|www\.)[a-zA-Z0-9.\-_~:/?#\[\]@!$&'()*+,;=%]+")
_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://")


def extract_urls(text: str) -> List[str]:
    """Extracts URLs from message text and strips trailing punctuation."""
    cleaned: List[str] = []
    for url in _URL_RE.findall(text):
        url = url.rstrip(".,)]?!;:'\"")
        if url and url not in cleaned:
            cleaned.append(url)
    return cleaned


def _normalize(url: str) -> str:
    return url if _SCHEME_RE.match(url) else "https://" + url


def _fallback_evidence(url: str) -> URLEvidence:
    """Used when a link couldn't be analyzed, so it still shows up in the results."""
    host = ""
    try:
        host = (urlparse(_normalize(url)).hostname or "").lower()
    except ValueError:
        pass
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        is_ip = False
    return URLEvidence(
        domain_age_days=None,
        ssl_valid=False,
        ssl_issuer=None,
        redirect_count=0,
        final_url=url,
        is_ip_address=is_ip,
        suspicious_tld=host.endswith(SUSPICIOUS_URL_TLDS),
        brand_impersonation=False,
        safe_browsing_hit=False,
        threat_intel=None,
    )


async def _analyze_one(url: str, semaphore: asyncio.Semaphore) -> URLEvidence:
    async with semaphore:
        try:
            return await asyncio.wait_for(analyze_url(_normalize(url)), timeout=PER_URL_TIMEOUT)
        except BlockedTarget as e:
            logger.warning("Skipped link '%s': %s", url, e)
        except asyncio.TimeoutError:
            logger.warning("Timed out analyzing link '%s'", url)
        except Exception:
            logger.exception("Failed to analyze extracted URL '%s'", url)
    return _fallback_evidence(url)


async def analyze_message_text(text: str) -> MessageEvidence:
    """Analyzes email/SMS text for phishing cues and returns MessageEvidence."""
    urgency_detected = bool(URGENCY_RE.search(text))
    financial_lures_detected = bool(FINANCIAL_RE.search(text))
    suspicious_phone_or_sender = any(p.search(text) for p in SUSPICIOUS_SENDER_PATTERNS)

    extracted_urls = extract_urls(text)[:MAX_URLS_PER_MESSAGE]

    # gather() keeps order, so url_evidences[i] always matches extracted_urls[i]
    semaphore = asyncio.Semaphore(URL_CONCURRENCY)
    url_evidences = list(await asyncio.gather(*(_analyze_one(u, semaphore) for u in extracted_urls)))

    return MessageEvidence(
        urgency_detected=urgency_detected,
        financial_lures_detected=financial_lures_detected,
        suspicious_phone_or_sender=suspicious_phone_or_sender,
        extracted_urls=extracted_urls,
        url_evidences=url_evidences,
    )
