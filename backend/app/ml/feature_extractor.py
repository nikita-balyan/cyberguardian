import ipaddress
import math
import re
from collections import Counter
from urllib.parse import urlparse

# Lowercase only: the TLD is lowercased before the lookup
SUSPICIOUS_TLDS = {
    'xyz', 'top', 'loan', 'club', 'click', 'link', 'work', 'party',
    'gq', 'ml', 'cf', 'tk', 'ga', 'cc', 'su', 'buzz', 'rest', 'icu', 'site', 'online',
}

# Training and inference must both use this exact column order
FEATURE_ORDER = [
    "url_length", "hostname_length", "path_length", "shannon_entropy",
    "subdomain_count", "dot_count", "hyphen_count", "has_ip",
    "suspicious_tld", "digit_ratio", "path_depth", "https_status",
]

_SCHEME_RE = re.compile(r'^[a-zA-Z][a-zA-Z0-9+.\-]*://')


def compute_entropy(text: str) -> float:
    """Shannon entropy of a string."""
    if not text:
        return 0.0
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in Counter(text).values())


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _parse(url: str):
    """Returns (scheme, hostname, path). Scheme-less input like 'example.com/login'
    still gets a hostname, but its scheme stays empty (https_status = 0)."""
    target = url if _SCHEME_RE.match(url) else "//" + url
    try:
        parsed = urlparse(target)
        return parsed.scheme.lower(), (parsed.hostname or "").lower(), parsed.path or ""
    except ValueError:  # malformed, e.g. an unclosed IPv6 bracket
        return "", "", ""


def extract_url_features(url: str) -> dict:
    """
    Extracts 12 lexical features from a URL string.

    1.  url_length       length of the URL as given
    2.  hostname_length  length of the hostname
    3.  path_length      length of the path
    4.  shannon_entropy  Shannon entropy of the URL
    5.  subdomain_count  labels left of the registered domain (approximate:
                         dots in hostname minus 1; 0 for IPs)
    6.  dot_count        '.' characters in the URL
    7.  hyphen_count     '-' characters in the URL
    8.  has_ip           1 if the hostname is an IPv4 or IPv6 address
    9.  suspicious_tld   1 if the TLD is in SUSPICIOUS_TLDS
    10. digit_ratio      digits / URL length
    11. path_depth       number of non-empty path segments
    12. https_status     1 if the scheme is https
    """
    url = str(url).strip()
    scheme, hostname, path = _parse(url)

    url_length = len(url)
    has_ip = 1 if _is_ip(hostname) else 0
    tld = hostname.rsplit('.', 1)[-1] if ('.' in hostname and not has_ip) else ""
    subdomain_count = 0 if (not hostname or has_ip) else max(0, hostname.count('.') - 1)
    digit_count = sum(c.isdigit() for c in url)

    features = {
        "url_length": url_length,
        "hostname_length": len(hostname),
        "path_length": len(path),
        "shannon_entropy": compute_entropy(url),
        "subdomain_count": subdomain_count,
        "dot_count": url.count('.'),
        "hyphen_count": url.count('-'),
        "has_ip": has_ip,
        "suspicious_tld": 1 if tld in SUSPICIOUS_TLDS else 0,
        "digit_ratio": (digit_count / url_length) if url_length else 0.0,
        "path_depth": len([seg for seg in path.split('/') if seg]),
        "https_status": 1 if scheme == 'https' else 0,
    }
    return {k: features[k] for k in FEATURE_ORDER}

def host_only_url(url: str) -> str:
    """Reduce a URL to 'http://<hostname>': no path, query, port, scheme, or leading www.
    The training data is lopsided on paths and schemes, so the ML model only sees the host."""
    _, hostname, _ = _parse(str(url).strip())
    if hostname.startswith("www."):
        hostname = hostname[4:]
    return "http://" + hostname if hostname else ""