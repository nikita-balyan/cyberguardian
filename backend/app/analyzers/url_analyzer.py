#url_analyzer.py
import asyncio
import ipaddress
import logging
import re
import socket
import ssl
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urljoin, urlparse

import httpx
import whois

from ..models.schemas import URLEvidence
from ..services.threat_intel import ThreatIntelService
from ..ml.inference import predict_phishing_probability
from ..ml.feature_extractor import extract_url_features

try:  # bundled public-suffix snapshot, no network call
    import tldextract
    _TLD_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)
except Exception:  # pragma: no cover - fallback if the package isn't installed
    _TLD_EXTRACT = None

logger = logging.getLogger(__name__)

SUSPICIOUS_TLDS = {".xyz", ".top", ".buzz", ".tk", ".cc", ".gq", ".ml", ".ga", ".work", ".loan", ".click"}
POPULAR_BRANDS = ["sbi", "hdfc", "paytm", "google", "amazon", "paypal", "netflix", "apple", "microsoft", "icici"]
LEGIT_BRAND_SUFFIXES = ("com", "in", "co.in")  # must be defined BEFORE BRAND_LEGIT below

# brand -> registered domains that genuinely belong to it (not exhaustive; extend as needed)
EXTRA_BRANDS = {
    "roblox": {"roblox.com"},
    "trezor": {"trezor.io"},
    "metamask": {"metamask.io", "consensys.io"},
    "whatsapp": {"whatsapp.com", "whatsapp.net"},
    "facebook": {"facebook.com", "facebook.net", "facebookmail.com", "fb.com"},
    "instagram": {"instagram.com", "cdninstagram.com"},
    "discord": {"discord.com", "discord.gg", "discordapp.com", "discordapp.net"},
    "tiktok": {"tiktok.com", "tiktokv.com", "tiktokcdn.com"},
    "binance": {"binance.com"},
    "coinbase": {"coinbase.com"},
    # real domains that contain a popular brand name
    "microsoft": {"microsoftonline.com", "microsoft365.com", "microsoftstore.com"},
    "google": {"googleapis.com", "googleusercontent.com", "googlevideo.com", "googlesyndication.com", "googletagmanager.com", "googlemail.com"},
    "amazon": {"amazonaws.com", "amazon.co.uk", "amazon.de", "amazon.ca", "amazon.com.au", "amazonpay.in"},
    "paypal": {"paypal.me", "paypalobjects.com", "paypal.co.uk"},
}

BRAND_LEGIT = {b: {f"{b}.{s}" for s in LEGIT_BRAND_SUFFIXES} for b in POPULAR_BRANDS}
for _brand, _domains in EXTRA_BRANDS.items():
    BRAND_LEGIT.setdefault(_brand, set()).update(_domains)

MAX_REDIRECTS = 5
ALLOWED_PORTS = {None, 80, 443, 8080, 8443}
FETCH_TOTAL_TIMEOUT = 8.0
SSL_TIMEOUT = 5.0
WHOIS_TIMEOUT = 6.0


class BlockedTarget(ValueError):
    """The target can't be scanned (private address, bad scheme, odd port...)."""


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def registered_domain(hostname: str) -> str:
    """'shop.example.co.in' -> 'example.co.in' (falls back to the last two labels)."""
    host = (hostname or "").lower().strip(".")
    if not host:
        return ""
    if _TLD_EXTRACT is not None:
        try:
            return _TLD_EXTRACT(host).registered_domain or host
        except Exception:
            pass
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def _is_public_ip(ip) -> bool:
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ip.is_global


def is_private_ip(hostname: str) -> bool:
    """Legacy synchronous check, kept for backward compatibility.
    analyze_url() uses resolve_public() instead."""
    if not hostname:
        return True
    if hostname.lower() == "localhost":
        return True
    try:
        return not _is_public_ip(ipaddress.ip_address(hostname))
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
        return any(not _is_public_ip(ipaddress.ip_address(i[4][0].split("%")[0])) for i in infos)
    except Exception:
        return False


async def resolve_public(hostname: str) -> bool:
    """True if the host resolves and EVERY address is public.
    False if it doesn't resolve. Raises BlockedTarget if any address is
    private, loopback, link-local, or otherwise reserved."""
    if not hostname or hostname.lower() == "localhost":
        raise BlockedTarget("Private and local addresses can't be scanned.")
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return False
    for info in infos:
        if not _is_public_ip(ipaddress.ip_address(info[4][0].split("%")[0])):
            raise BlockedTarget("Private and local addresses can't be scanned.")
    return True


async def safe_fetch(url: str) -> tuple[str, int]:
    """Follow redirects manually, re-validating EVERY hop.
    Only response headers are read, never the body. Returns (final_url, hops)."""
    current, hops = url, 0
    async with httpx.AsyncClient(follow_redirects=False, timeout=3.0) as client:
        while True:
            parsed = urlparse(current)
            if parsed.scheme not in ("http", "https") or not parsed.hostname:
                raise BlockedTarget("Only http and https links can be scanned.")
            if parsed.port not in ALLOWED_PORTS:
                raise BlockedTarget("Links using unusual ports can't be scanned.")
            if not await resolve_public(parsed.hostname):
                return current, hops  # dead domain: keep analyzing, skip network probes
            async with client.stream("GET", current) as resp:
                location = resp.headers.get("location")
                if resp.is_redirect and location and hops < MAX_REDIRECTS:
                    current = urljoin(current, location)
                    hops += 1
                    continue
                return str(resp.url), hops


async def _in_thread(fn, *args, timeout: float, default):
    """Run a blocking call off the event loop with a hard timeout."""
    try:
        return await asyncio.wait_for(asyncio.to_thread(fn, *args), timeout=timeout)
    except Exception as e:
        logger.debug(f"{getattr(fn, '__name__', 'call')} failed or timed out: {e}")
        return default


# --------------------------------------------------------------------------- #
# Individual checks
# --------------------------------------------------------------------------- #
def check_ssl(hostname: str) -> tuple[bool, Optional[str]]:
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=3.0) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                if not cert:
                    return False, None

                not_after = cert.get("notAfter")
                if not_after:
                    expiry_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    if datetime.now(timezone.utc) > expiry_date:
                        return False, "Expired SSL Certificate"

                issuer = cert.get("issuer")
                issuer_str = "Unknown"
                if issuer:
                    for item in issuer:
                        if item and item[0][0] == "commonName":
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
        if creation_date and isinstance(creation_date, datetime):
            if creation_date.tzinfo is None:
                creation_date = creation_date.replace(tzinfo=timezone.utc)
            return max(0, (datetime.now(timezone.utc) - creation_date).days)
    except Exception as e:
        logger.debug(f"WHOIS lookup failed for {domain}: {e}")
    return None


def _token_hits_brand(token: str, brand: str) -> bool:
    if token == brand:
        return True
    # longer brands also match as a prefix or suffix ("paypalsecure", "securepaypal")
    return len(brand) >= 5 and (token.startswith(brand) or token.endswith(brand))

def check_brand_impersonation(hostname: str) -> bool:
    """Flags hosts that use a brand name but aren't that brand's own domain."""
    host = (hostname or "").lower().strip(".")
    if not host:
        return False
    reg = registered_domain(host)
    tokens = {t for label in host.split(".") for t in re.split(r"[^a-z]+", label) if t}
    for brand, legit_domains in BRAND_LEGIT.items():
        if any(_token_hits_brand(t, brand) for t in tokens) and reg not in legit_domains:
            return True
    return False

# --------------------------------------------------------------------------- #
# Main entry point
# --------------------------------------------------------------------------- #
async def analyze_url(url: str) -> URLEvidence:
    url = url.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", url):
        url = "https://" + url
    elif not url.lower().startswith(("http://", "https://")):
        raise BlockedTarget("Only http and https links can be scanned.")

    parsed = urlparse(url)
    hostname = parsed.hostname
    if not hostname:
        raise ValueError("Invalid URL: missing hostname")

    # Is the hostname a raw IP?
    try:
        ipaddress.ip_address(hostname)
        is_ip = True
    except ValueError:
        is_ip = False

    # Follow redirects safely: every hop is re-checked against private ranges (SSRF)
    redirect_count = 0
    final_url = url
    try:
        final_url, redirect_count = await asyncio.wait_for(safe_fetch(url), timeout=FETCH_TOTAL_TIMEOUT)
    except BlockedTarget:
        raise
    except Exception as e:
        logger.debug(f"HTTP request/redirect tracking failed for {url}: {e}")

    final_parsed = urlparse(final_url)
    final_hostname = final_parsed.hostname or hostname

    # SSL and WHOIS are blocking, so run them in threads with timeouts
    ssl_valid, ssl_issuer = await _in_thread(check_ssl, final_hostname, timeout=SSL_TIMEOUT, default=(False, None))
    whois_domain = registered_domain(final_hostname) or final_hostname
    domain_age_days = await _in_thread(get_domain_age_days, whois_domain, timeout=WHOIS_TIMEOUT, default=None)

    suspicious_tld = any(final_hostname.endswith(tld) for tld in SUSPICIOUS_TLDS)
    brand_impersonation = check_brand_impersonation(final_hostname)

    threat_intel_service = ThreatIntelService()
    threat_intel = await threat_intel_service.lookup(final_url)
    safe_browsing_hit = (
        threat_intel.get("sources", {}).get("google_safebrowsing", {}).get("flagged", False)
        or threat_intel.get("flagged", False)
    )

    ml_probability = predict_phishing_probability(final_url)
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