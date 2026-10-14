"""URL structural and lexical feature extraction and heuristic risk analysis."""

import math
import re
from urllib.parse import urlparse
from typing import Dict, Any, List


# Suspicious keywords commonly seen in credential harvesting URLs
SUSPICIOUS_URL_KEYWORDS = [
    "login", "verify", "account", "update", "banking", "secure", "security",
    "confirm", "signin", "password", "credential", "wallet", "support",
    "validation", "recover", "authenticate", "billing", "invoice", "portal"
]

# Suspicious Top-Level Domains (TLDs) frequently abused in disposable phishing campaigns
SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".club", ".work", ".click", ".buzz", ".live", ".fit",
    ".tk", ".ml", ".ga", ".cf", ".gq", ".country", ".stream", ".gdn", ".kim", ".rest"
}

# Known URL shortener domains
SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "ow.ly", "buff.ly", "tiny.cc",
    "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy"
}

# Regex to detect raw IPv4 addresses in hostname
IPV4_REGEX = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")

# Typosquatting / brand target keywords
BRAND_KEYWORDS = ["google", "microsoft", "apple", "amazon", "paypal", "netflix", "facebook", "chase", "wellsfargo", "bankofamerica"]


def calculate_shannon_entropy(text: str) -> float:
    """Calculate Shannon entropy to detect algorithmic random domain generation (DGA)."""
    if not text:
        return 0.0
    entropy = 0.0
    text_len = len(text)
    char_counts = {}
    for char in text:
        char_counts[char] = char_counts.get(char, 0) + 1
    for count in char_counts.values():
        p = count / text_len
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def parse_and_clean_url(raw_url: str) -> tuple[str, str, str]:
    """Ensure URL has a scheme for parsing, return (clean_url, hostname, path)."""
    clean_url = raw_url.strip()
    if not clean_url.startswith(("http://", "https://")):
        # Prepend http:// for parsing purposes only
        parsed = urlparse(f"http://{clean_url}")
    else:
        parsed = urlparse(clean_url)
    hostname = (parsed.hostname or "").lower()
    path = parsed.path or ""
    return clean_url, hostname, path


def extract_url_features(raw_url: str) -> Dict[str, Any]:
    """
    Extract numerical and categorical lexical features from a URL.
    This feature set is used by both the ML classifier and transparency dashboards.
    """
    clean_url, hostname, path = parse_and_clean_url(raw_url)
    url_length = len(clean_url)
    host_length = len(hostname)
    
    # Check IP address as hostname
    is_ip_hostname = 1 if IPV4_REGEX.match(hostname) else 0
    
    # Scheme features
    uses_https = 1 if clean_url.lower().startswith("https://") else 0
    has_at_symbol = 1 if "@" in clean_url else 0
    has_double_slash_redirect = 1 if clean_url.count("//") > 1 else 0
    
    # Character counts
    count_dots = clean_url.count(".")
    count_hyphens = clean_url.count("-")
    count_underscores = clean_url.count("_")
    count_digits = sum(c.isdigit() for c in clean_url)
    digit_ratio = round(count_digits / max(url_length, 1), 4)
    
    # Subdomain depth
    host_parts = hostname.split(".")
    subdomain_count = max(0, len(host_parts) - 2) if not is_ip_hostname else 0
    
    # Suspicious TLD check
    tld_match = any(hostname.endswith(tld) for tld in SUSPICIOUS_TLDS)
    is_suspicious_tld = 1 if tld_match else 0
    
    # Shortener check
    is_shortener = 1 if any(short in hostname for short in SHORTENER_DOMAINS) else 0
    
    # Keywords count
    keyword_count = sum(1 for kw in SUSPICIOUS_URL_KEYWORDS if kw in clean_url.lower())
    
    # Entropy
    url_entropy = calculate_shannon_entropy(clean_url)
    host_entropy = calculate_shannon_entropy(hostname)
    
    return {
        "url_length": url_length,
        "host_length": host_length,
        "is_ip_hostname": is_ip_hostname,
        "uses_https": uses_https,
        "has_at_symbol": has_at_symbol,
        "has_double_slash_redirect": has_double_slash_redirect,
        "count_dots": count_dots,
        "count_hyphens": count_hyphens,
        "count_underscores": count_underscores,
        "digit_ratio": digit_ratio,
        "subdomain_count": subdomain_count,
        "is_suspicious_tld": is_suspicious_tld,
        "is_shortener": is_shortener,
        "keyword_count": keyword_count,
        "url_entropy": url_entropy,
        "host_entropy": host_entropy,
        # Metadata
        "hostname": hostname,
        "clean_url": clean_url,
    }


def extract_url_heuristic_indicators(raw_url: str) -> Dict[str, Any]:
    """
    Extract rule-based heuristic security indicators from a URL.
    
    Returns structured explanation of warning indicators.
    Note: These indicators are transparent rules and NOT claimed to be ML predictions.
    """
    features = extract_url_features(raw_url)
    hostname = features["hostname"]
    clean_url = features["clean_url"]
    indicators: List[Dict[str, Any]] = []

    # 1. Raw IP Hostname
    if features["is_ip_hostname"]:
        indicators.append({
            "category": "Hostname",
            "name": "Direct IP Address Hostname",
            "severity": "HIGH",
            "description": f"The target URL connects directly to raw numerical IP '{hostname}', bypassing standard DNS domain validation.",
        })

    # 2. Credential/Redirection Symbol (@)
    if features["has_at_symbol"]:
        indicators.append({
            "category": "Authentication Obfuscation",
            "name": "Presence of '@' Symbol",
            "severity": "HIGH",
            "description": "The '@' character causes browsers to treat prefix text as credentials and navigate to the succeeding domain, a classic spoofing technique.",
        })

    # 3. Double Slash in Path
    if features["has_double_slash_redirect"]:
        indicators.append({
            "category": "Redirection",
            "name": "Internal Path Double-Slash ('//')",
            "severity": "MEDIUM",
            "description": "Subsequent '//' in the URL path often indicates an open-redirect exploit forwarding users to an external destination.",
        })

    # 4. Excessive Subdomains
    if features["subdomain_count"] >= 3:
        indicators.append({
            "category": "DNS Hierarchy",
            "name": f"Excessive Subdomain Depth ({features['subdomain_count']} levels)",
            "severity": "MEDIUM",
            "description": f"Abnormal number of subdomains ('{hostname}') designed to mimic legitimate domain structures while using attacker-controlled root domains.",
        })

    # 5. Non-HTTPS / Cleartext HTTP
    if not features["uses_https"]:
        indicators.append({
            "category": "Transport Encryption",
            "name": "Insecure Cleartext Protocol (HTTP)",
            "severity": "MEDIUM",
            "description": "The URL uses unencrypted HTTP. Legitimate financial, login, and corporate portals mandate TLS/HTTPS.",
        })

    # 6. High-Risk TLD
    if features["is_suspicious_tld"]:
        matching_tlds = [tld for tld in SUSPICIOUS_TLDS if hostname.endswith(tld)]
        indicators.append({
            "category": "Top-Level Domain",
            "name": f"High-Risk TLD Abuse ({', '.join(matching_tlds)})",
            "severity": "MEDIUM",
            "description": "Uses a cheap or historically abusive top-level domain frequently utilized in bulk throwaway phishing deployments.",
        })

    # 7. URL Shortener Service
    if features["is_shortener"]:
        indicators.append({
            "category": "Cloaking",
            "name": "URL Shortener / Masking Service",
            "severity": "LOW",
            "description": "Shortening services mask the real destination hostname and query path until clicked.",
        })

    # 8. Excessive Length or High Entropy
    if features["url_length"] > 90:
        indicators.append({
            "category": "Length Anomaly",
            "name": f"Unusually Long URL ({features['url_length']} chars)",
            "severity": "LOW",
            "description": "Lengthy URLs are often created by affiliate tokens, tracking tokens, or attempts to push the actual domain out of address bar view.",
        })
    if features["host_entropy"] > 3.6 and not features["is_ip_hostname"]:
        indicators.append({
            "category": "Domain Randomness",
            "name": f"Elevated Shannon Entropy ({features['host_entropy']})",
            "severity": "MEDIUM",
            "description": "High character unpredictability in the hostname suggests Domain Generation Algorithms (DGA) or randomized hosting.",
        })

    # 9. Brand Name in Subdomain or Path (Possible Typosquatting / Impersonation)
    found_brands = [b for b in BRAND_KEYWORDS if b in clean_url.lower() and not hostname.endswith(f"{b}.com")]
    if found_brands and not any(hostname == f"{b}.com" or hostname.endswith(f".{b}.com") for b in found_brands):
        indicators.append({
            "category": "Brand Deception",
            "name": f"Brand Keyword in Non-Official Domain ({', '.join(found_brands)})",
            "severity": "HIGH",
            "description": f"URL mentions brand '{', '.join(found_brands)}' but is not hosted on that brand's official domain.",
        })

    # Severity counts
    high_count = sum(1 for ind in indicators if ind["severity"] == "HIGH")
    med_count = sum(1 for ind in indicators if ind["severity"] == "MEDIUM")
    low_count = sum(1 for ind in indicators if ind["severity"] == "LOW")

    return {
        "features": features,
        "indicators": indicators,
        "total_indicators": len(indicators),
        "high_severity_count": high_count,
        "medium_severity_count": med_count,
        "low_severity_count": low_count,
    }
