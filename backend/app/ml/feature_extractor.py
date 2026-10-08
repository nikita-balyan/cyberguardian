import re
import math
from urllib.parse import urlparse

# List of suspicious TLDs often associated with phishing
SUSPICIOUS_TLDS = {
    'xyz', 'top', 'loan', 'club', 'click', 'link', 'work', 'party', 
    'gq', 'ml', 'cf', 'tk', 'cc', 'su', 'buzz', 'Rest', 'icu', 'site', 'online'
}

def compute_entropy(text: str) -> float:
    """Computes Shannon entropy of a string."""
    if not text:
        return 0.0
    entropy = 0.0
    length = len(text)
    # Count character frequencies
    counts = {}
    for char in text:
        counts[char] = counts.get(char, 0) + 1
    
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy

def extract_url_features(url: str) -> dict:
    """
    Extracts 12 lexical metrics from a given URL string.
    
    Metrics:
    1. url_length: Total length of the URL string.
    2. hostname_length: Length of the hostname.
    3. path_length: Length of the path component.
    4. shannon_entropy: Shannon entropy of the URL string.
    5. subdomain_count: Number of subdomains (dots in hostname minus 1, min 0).
    6. dot_count: Total count of dots '.' in the URL.
    7. hyphen_count: Total count of hyphens '-' in the URL.
    8. has_ip: Binary indicator (1 if hostname is an IPv4/IPv6 address, else 0).
    9. suspicious_tld: Binary indicator (1 if TLD is in SUSPICIOUS_TLDS, else 0).
    10. digit_ratio: Ratio of digits to total characters in the URL.
    11. path_depth: Number of slashes '/' in the path.
    12. https_status: Binary indicator (1 if scheme is https, else 0).
    """
    if not isinstance(url, str):
        url = str(url)
        
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    path = parsed.path or ""
    
    # 1. url_length
    url_length = len(url)
    
    # 2. hostname_length
    hostname_length = len(hostname)
    
    # 3. path_length
    path_length = len(path)
    
    # 4. shannon_entropy
    shannon_entropy = compute_entropy(url)
    
    # 5. subdomain_count
    # e.g., login.example.com -> hostname has 2 dots, subdomains = 2 - 1 = 1
    subdomain_count = max(0, hostname.count('.')) - 1 if hostname else 0
    
    # 6. dot_count
    dot_count = url.count('.')
    
    # 7. hyphen_count
    hyphen_count = url.count('-')
    
    # 8. has_ip (IPv4 regex check)
    ipv4_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    has_ip = 1 if re.match(ipv4_pattern, hostname) else 0
    
    # 9. suspicious_tld
    tld = hostname.split('.')[-1].lower() if '.' in hostname else ""
    suspicious_tld = 1 if tld in SUSPICIOUS_TLDS else 0
    
    # 10. digit_ratio
    digit_count = sum(c.isdigit() for c in url)
    digit_ratio = (digit_count / url_length) if url_length > 0 else 0.0
    
    # 11. path_depth
    path_depth = path.strip('/').count('/') + 1 if path and path != '/' else (1 if path == '/' else 0)
    
    # 12. https_status
    https_status = 1 if parsed.scheme.lower() == 'https' else 0
    
    return {
        "url_length": url_length,
        "hostname_length": hostname_length,
        "path_length": path_length,
        "shannon_entropy": shannon_entropy,
        "subdomain_count": subdomain_count,
        "dot_count": dot_count,
        "hyphen_count": hyphen_count,
        "has_ip": has_ip,
        "suspicious_tld": suspicious_tld,
        "digit_ratio": digit_ratio,
        "path_depth": path_depth,
        "https_status": https_status
    }
