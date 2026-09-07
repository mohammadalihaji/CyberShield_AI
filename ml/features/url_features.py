import math
import re
import ipaddress
from urllib.parse import urlparse, unquote
from collections import Counter
from typing import Dict, Any, List

# Known URL shorteners
SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "ow.ly", "goo.gl",
    "tiny.cc", "tr.im", "rebrand.ly", "cutt.ly", "rb.gy", "shorturl.at",
    "clck.ru", "shorte.st", "adf.ly", "bc.vc", "linkshrink.net"
}

# High-risk / abuse-heavy TLDs frequently seen in bulk phishing
SUSPICIOUS_TLDS = {
    "top", "xyz", "click", "fit", "work", "loan", "gq", "cf", "tk", "ml",
    "ga", "icu", "buzz", "rest", "monster", "sbs", "cam", "quest", "cfd",
    "live", "surf", "hair", "skin", "beauty", "boats", "cyou", "racing"
}

# Phishing and credential lures
SUSPICIOUS_KEYWORDS = [
    "login", "signin", "sign-in", "verify", "verification", "account",
    "update", "security", "secure", "banking", "wallet", "confirm",
    "authentication", "authenticate", "credential", "recover", "recovery",
    "alert", "billing", "invoice", "payment", "ebayisapi", "webscr", "password"
]

# High-target brands for brand impersonation detection
HIGH_TARGET_BRANDS = [
    "paypal", "google", "apple", "microsoft", "netflix", "amazon",
    "facebook", "instagram", "chase", "wellsfargo", "bankofamerica",
    "binance", "coinbase", "steam", "dhl", "fedex", "ups", "irs", "att"
]


def calculate_entropy(text: str) -> float:
    """Calculates the Shannon entropy of a string."""
    if not text:
        return 0.0
    length = len(text)
    counts = Counter(text)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def extract_base_domain(hostname: str) -> str:
    """Extracts the registered base domain (e.g., example.com from sub.example.com)."""
    if not hostname:
        return ""
    hostname = hostname.lower().strip()
    
    # Handle port if included
    if ":" in hostname:
        hostname = hostname.split(":")[0]

    # Handle IP address
    try:
        ipaddress.ip_address(hostname)
        return hostname
    except ValueError:
        pass

    # Basic multi-part TLD handling
    parts = hostname.split(".")
    if len(parts) <= 2:
        return hostname

    two_part_tlds = {"co.uk", "gov.uk", "ac.uk", "com.au", "net.au", "co.nz", "com.br", "co.jp", "co.in", "net.in", "org.in", "gov.in"}
    last_two = ".".join(parts[-2:])
    if last_two in two_part_tlds and len(parts) >= 3:
        return ".".join(parts[-3:])
    
    return ".".join(parts[-2:])


def extract_url_features(url: str) -> Dict[str, Any]:
    """
    Extracts comprehensive, reproducible lexical, structural, and statistical features from a URL.
    Returns a dictionary of numerical / boolean features suitable for ML model consumption.
    """
    if not url:
        url = ""
    
    # Pre-normalize for parsing
    clean_url = url.strip()
    if not clean_url.startswith(("http://", "https://")):
        clean_url = "https://" + clean_url
        
    try:
        parsed = urlparse(clean_url)
    except Exception:
        parsed = urlparse("https://invalid.url")

    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""
    fragment = parsed.fragment or ""

    # Check for IP address
    is_ip = 0
    try:
        if hostname:
            ipaddress.ip_address(hostname)
            is_ip = 1
    except ValueError:
        is_ip = 0

    # Ports
    port = parsed.port
    has_port = 1 if port is not None else 0
    is_suspicious_port = 1 if port is not None and port not in (80, 443, 8080, 8443) else 0

    # Subdomains & TLD
    base_domain = extract_base_domain(hostname)
    tld = hostname.split(".")[-1] if "." in hostname and not is_ip else ""
    
    subdomain_part = ""
    subdomain_count = 0
    if hostname and base_domain and hostname != base_domain and not is_ip:
        subdomain_part = hostname[:-(len(base_domain) + 1)]
        subdomain_count = len(subdomain_part.split("."))

    # Character counts & statistics
    url_len = len(clean_url)
    host_len = len(hostname)
    path_len = len(path)
    query_len = len(query)
    frag_len = len(fragment)

    num_dots = clean_url.count(".")
    num_hyphens = clean_url.count("-")
    num_underscores = clean_url.count("_")
    num_slashes = clean_url.count("/")
    num_percent = clean_url.count("%")
    num_at = clean_url.count("@")
    num_double_slash_path = 1 if "//" in path else 0
    num_question_marks = clean_url.count("?")
    num_equal_signs = clean_url.count("=")
    num_ampersands = clean_url.count("&")
    
    digits = re.findall(r"\d", clean_url)
    num_digits = len(digits)
    digit_ratio = num_digits / max(url_len, 1)

    special_chars = re.findall(r"[^a-zA-Z0-9]", clean_url)
    num_special_chars = len(special_chars)
    special_char_ratio = num_special_chars / max(url_len, 1)

    # Entropies
    url_entropy = calculate_entropy(clean_url)
    host_entropy = calculate_entropy(hostname)
    path_entropy = calculate_entropy(path)
    query_entropy = calculate_entropy(query)

    # Heuristic and structural indicators
    is_https = 1 if scheme == "https" else 0
    is_punycode = 1 if "xn--" in hostname else 0
    is_shortened = 1 if hostname in SHORTENER_DOMAINS or base_domain in SHORTENER_DOMAINS else 0
    suspicious_tld = 1 if tld in SUSPICIOUS_TLDS else 0
    excessive_encoding = 1 if num_percent >= 3 else 0

    # Keyword checks
    url_lower = clean_url.lower()
    path_query_lower = (path + "?" + query).lower()
    
    suspicious_kw_count = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url_lower)
    
    # Brand impersonation heuristics (e.g. brand name in subdomain/path but base domain is different)
    brand_kw_count = 0
    brand_in_subdomain_or_path = 0
    for brand in HIGH_TARGET_BRANDS:
        if brand in url_lower:
            brand_kw_count += 1
            # If brand is present in the URL, but the base_domain is NOT that brand's official domain
            if brand in (subdomain_part + "/" + path_query_lower) and brand not in base_domain:
                brand_in_subdomain_or_path = 1

    return {
        "url_length": url_len,
        "hostname_length": host_len,
        "path_length": path_len,
        "query_length": query_len,
        "fragment_length": frag_len,
        "num_dots": num_dots,
        "num_hyphens": num_hyphens,
        "num_underscores": num_underscores,
        "num_slashes": num_slashes,
        "num_percent": num_percent,
        "num_at": num_at,
        "num_double_slash_path": num_double_slash_path,
        "num_question_marks": num_question_marks,
        "num_equal_signs": num_equal_signs,
        "num_ampersands": num_ampersands,
        "num_digits": num_digits,
        "num_special_chars": num_special_chars,
        "digit_ratio": round(digit_ratio, 4),
        "special_char_ratio": round(special_char_ratio, 4),
        "subdomain_count": subdomain_count,
        "subdomain_length": len(subdomain_part),
        "url_entropy": round(url_entropy, 4),
        "hostname_entropy": round(host_entropy, 4),
        "path_entropy": round(path_entropy, 4),
        "query_entropy": round(query_entropy, 4),
        "is_ip_address": is_ip,
        "has_port_in_url": has_port,
        "is_suspicious_port": is_suspicious_port,
        "is_punycode": is_punycode,
        "is_https": is_https,
        "has_at_symbol": 1 if num_at > 0 else 0,
        "excessive_percent_encoding": excessive_encoding,
        "is_shortened_url": is_shortened,
        "suspicious_tld_indicator": suspicious_tld,
        "suspicious_keywords_count": suspicious_kw_count,
        "brand_keywords_count": brand_kw_count,
        "brand_in_subdomain_or_path": brand_in_subdomain_or_path,
        "base_domain": base_domain,
        "hostname": hostname
    }
