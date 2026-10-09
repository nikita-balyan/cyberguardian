import ipaddress
import socket
import ssl
from datetime import datetime, timezone
import logging
from typing import Optional
from urllib.parse import urlparse
import httpx
import whois

from ..models.schemas import URLEvidence
from ..services.threat_intel import ThreatIntelService
from ..ml.inference import predict_phishing_probability
from ..ml.feature_extractor import extract_url_features

logger = logging.getLogger(__name__)

SUSPICIOUS_TLDS = {".xyz", ".top", ".buzz", ".tk", ".cc", ".gq", ".ml", ".ga", ".work", ".loan", ".click"}
POPULAR_BRANDS = ["sbi", "hdfc", "paytm", "google", "amazon", "paypal", "netflix", "apple", "microsoft", "icici"]


def is_private_ip(hostname: str) -> bool:
    if hostname.lower() == "localhost":
        return True
    try:
        ip = ipaddress.ip_address(hostname)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        # Not a raw IP string, check if resolves to private IP
        try:
            resolved_ip = socket.gethostbyname(hostname)
            ip = ipaddress.ip_address(resolved_ip)
            return ip.is_private or ip.is_loopback or ip.is_link_local
        except Exception:
            return False


def check_ssl(hostname: str) -> tuple[bool, Optional[str]]:
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=3.0) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                if not cert:
                    return False, None

                # Check expiration
                not_after = cert.get('notAfter')
                if not_after:
                    # Parse SSL expiration date and enforce UTC timezone
                    expiry_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    if datetime.now(timezone.utc) > expiry_date:
                        return False, "Expired SSL Certificate"

                issuer = cert.get('issuer')
                issuer_str = "Unknown"
                if issuer:
                    for item in issuer:
                        if item and item[0][0] == 'commonName':
                            issuer_str = item[0][1]
                            break
                    if issuer_str == "Unknown" and len(issuer) > 0 and len(issuer[0]) > 0:
                        issuer_str = str(issuer[0])

                return True, issuer_str
    except Exception as e:
        logger.debug(f"SSL check failed for {hostname}: {e}")
        return False, None


def get_domain_age_days(domain: str) -> Optional[int]:
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date:
            if isinstance(creation_date, datetime):
                # Ensure creation_date is timezone-aware UTC for arithmetic comparison
                if creation_date.tzinfo is None:
                    creation_date = creation_date.replace(tzinfo=timezone.utc)
                delta = datetime.now(timezone.utc) - creation_date
                return max(0, delta.days)
    except Exception as e:
        logger.debug(f"WHOIS lookup failed for {domain}: {e}")
    return None


def check_brand_impersonation(hostname: str) -> bool:
    hostname_lower = hostname.lower()
    for brand in POPULAR_BRANDS:
        if brand in hostname_lower:
            if not hostname_lower.endswith(f"{brand}.com") and not hostname_lower.endswith(f"{brand}.in") and hostname_lower != f"www.{brand}.com" and hostname_lower != f"{brand}.com":
                return True
    return False


async def analyze_url(url: str) -> URLEvidence:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)
    hostname = parsed.hostname

    if not hostname:
        raise ValueError("Invalid URL: missing hostname")

    # 1. Validate against SSRF
    if is_private_ip(hostname):
        raise ValueError("SSRF protection: Private IP ranges or localhost are not allowed.")

    # 2. Check if hostname is a raw IP
    is_ip = False
    try:
        ipaddress.ip_address(hostname)
        is_ip = True
    except ValueError:
        is_ip = False

    # 3. Track HTTP redirect chains (max 5 hops) using httpx.AsyncClient with 3s timeout
    redirect_count = 0
    final_url = url
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=3.0) as client:
            response = await client.get(url)
            final_url = str(response.url)
            redirect_count = len(response.history)
            if redirect_count > 5:
                redirect_count = 5
    except Exception as e:
        logger.debug(f"HTTP request/redirect tracking failed for {url}: {e}")

    # Parse final hostname for SSL & WHOIS
    final_parsed = urlparse(final_url)
    final_hostname = final_parsed.hostname or hostname

    # 4. Check SSL certificate validity and issuer
    ssl_valid, ssl_issuer = check_ssl(final_hostname)

    # 5. Extract domain registration date using whois and calculate age in days
    domain_parts = final_hostname.split('.')
    if len(domain_parts) >= 2:
        whois_domain = ".".join(domain_parts[-2:])
    else:
        whois_domain = final_hostname

    domain_age_days = get_domain_age_days(whois_domain)

    # 6. Flag suspicious TLDs
    suspicious_tld = any(final_hostname.endswith(tld) for tld in SUSPICIOUS_TLDS)

    # 7. Basic brand-squatting detection
    brand_impersonation = check_brand_impersonation(final_hostname)

    # 8. Threat Intelligence Lookup (URLhaus & Google Safe Browsing)
    threat_intel_service = ThreatIntelService()
    threat_intel = await threat_intel_service.lookup(final_url)
    safe_browsing_hit = threat_intel.get("sources", {}).get("google_safebrowsing", {}).get("flagged", False) or threat_intel.get("flagged", False)

    # 9. Secondary ML Phishing Probability
    ml_probability = predict_phishing_probability(final_url)

    # 10. Extract 12 lexical features for telemetry
    lexical_features = extract_url_features(final_url)

    return URLEvidence(
        domain_age_days=domain_age_days,
        ssl_valid=ssl_valid,
        ssl_issuer=ssl_issuer,
        redirect_count=redirect_count,
        final_url=final_url,
        is_ip_address=is_ip,
        suspicious_tld=suspicious_tld,
        brand_impersonation=brand_impersonation,
        safe_browsing_hit=safe_browsing_hit,
        threat_intel=threat_intel,
        ml_probability=ml_probability,
        lexical_features=lexical_features,
    )


