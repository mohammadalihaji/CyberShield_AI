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
    "clck.ru", "shorte.st", "adf.ly", "bc.vc", "linkshrink.net", "0.gp", "0a.sk"
}

# Free hosting providers
FREE_HOSTING_DOMAINS = {
    "000webhost.com", "000webhostapp.com", "20m.com", "50webs.com", "altervista.org",
    "awardspace.com", "bravehost.com", "byethost.com", "epizy.com", "freewebhostmost.com",
    "github.io", "gitlab.io", "jimdofree.com", "netcities.net", "page.tl", "pantheonsite.io",
    "surge.sh", "tripod.com", "vercel.app", "weebly.com", "wixsite.com", "wordpress.com", "yolasite.com"
}

# High-risk / abuse-heavy TLDs frequently seen in bulk phishing
SUSPICIOUS_TLDS = {
    "top", "xyz", "click", "fit", "work", "loan", "gq", "cf", "tk", "ml",
    "ga", "icu", "buzz", "rest", "monster", "sbs", "cam", "quest", "cfd",
    "live", "surf", "hair", "skin", "beauty", "boats", "cyou", "racing"
}

# High-risk file extensions
HIGH_RISK_EXTENSIONS = {".exe", ".zip", ".scr", ".bat", ".apk", ".msi", ".dll", ".hta", ".cmd", ".ps1", ".jar"}

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
    
    if ":" in hostname:
        hostname = hostname.split(":")[0]

    try:
        ipaddress.ip_address(hostname)
        return hostname
    except ValueError:
        pass

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
    Extracts comprehensive, reproducible lexical, structural, statistical,
    and CompPhish V4 aligned URL features.
    """
    if not url:
        url = ""
    
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

    is_ip = 0
    try:
        if hostname:
            ipaddress.ip_address(hostname)
            is_ip = 1
    except ValueError:
        is_ip = 0

    port = parsed.port
    has_port = 1 if port is not None else 0
    is_suspicious_port = 1 if port is not None and port not in (80, 443, 8080, 8443) else 0

    base_domain = extract_base_domain(hostname)
    tld = hostname.split(".")[-1] if "." in hostname and not is_ip else ""
    
    subdomain_part = ""
    subdomain_count = 0
    if hostname and base_domain and hostname != base_domain and not is_ip:
        subdomain_part = hostname[:-(len(base_domain) + 1)]
        subdomain_count = len(subdomain_part.split("."))

    url_len = len(clean_url)
    host_len = len(hostname)
    path_len = len(path)
    query_len = len(query)

    num_dots = clean_url.count(".")
    num_hyphens = clean_url.count("-")
    num_underscores = clean_url.count("_")
    num_slashes = clean_url.count("/")
    num_percent = clean_url.count("%")
    num_at = clean_url.count("@")
    num_comma = clean_url.count(",")
    num_dollar = clean_url.count("$")
    num_semicolon = clean_url.count(";")
    num_space = clean_url.count(" ")
    num_ampersand = clean_url.count("&")
    num_equal = clean_url.count("=")
    num_question = clean_url.count("?")
    num_colon = clean_url.count(":")
    num_slashes_inpath = path.count("/")
    dots_path = path.count(".")

    has_asterisk = 1 if "*" in clean_url else 0
    has_or = 1 if "|" in clean_url else 0
    has_embedded_url = 1 if ("http://" in (path + query) or "https://" in (path + query)) else 0

    digits = re.findall(r"\d", clean_url)
    num_digits = len(digits)
    digit_ratio = num_digits / max(url_len, 1)

    host_digits = len(re.findall(r"\d", hostname))
    hostname_digit_ratio = host_digits / max(host_len, 1)

    special_chars = re.findall(r"[^a-zA-Z0-9]", clean_url)
    num_special_chars = len(special_chars)

    url_entropy = calculate_entropy(clean_url)
    host_entropy = calculate_entropy(hostname)
    path_entropy = calculate_entropy(path)
    query_entropy = calculate_entropy(query)

    is_https = 1 if scheme == "https" else 0
    is_punycode = 1 if "xn--" in hostname else 0
    is_shortened = 1 if hostname in SHORTENER_DOMAINS or base_domain in SHORTENER_DOMAINS else 0
    is_free_hosting = 1 if base_domain in FREE_HOSTING_DOMAINS or hostname in FREE_HOSTING_DOMAINS else 0

    url_lower = clean_url.lower()
    path_query_lower = (path + "?" + query).lower()
    
    brand_sub = 0
    brand_substr_dom = 0
    brand_path_query = 0
    for b in HIGH_TARGET_BRANDS:
        if b in subdomain_part:
            brand_sub = 1
        if b in hostname and b not in base_domain:
            brand_substr_dom = 1
        if b in path_query_lower and b not in base_domain:
            brand_path_query = 1

    words = re.findall(r"\w+", clean_url)
    total_words = len(words)
    avg_word_len = sum(len(w) for w in words) / max(total_words, 1)
    longest_word = max((len(w) for w in words), default=0)
    shortest_word = min((len(w) for w in words), default=0)

    has_high_risk_ext = 1 if any(path.lower().endswith(ext) for ext in HIGH_RISK_EXTENSIONS) else 0
    num_query_params = len(query.split("&")) if query else 0
    count_www = clean_url.lower().count("www")
    count_com = clean_url.lower().count("com")

    return {
        # CompPhish V4 exact feature schema (47 features)
        "brand_subdomain": brand_sub,
        "brand_substring_domain": brand_substr_dom,
        "brand_typo_dom": 0,
        "fake_tld": 1 if tld in SUSPICIOUS_TLDS else 0,
        "brand_in_path_query": brand_path_query,
        "dots_path": dots_path,
        "url_more_than_mean": 1 if url_len > 55 else 0,
        "domain_more_than_mean": 1 if host_len > 20 else 0,
        "gibberish": 1 if longest_word > 18 else 0,
        "domain_length": host_len,
        "url_length": url_len,
        "url_contains_ip": is_ip,
        "presence_of_url_shortner": is_shortened,
        "special_characters_count": num_special_chars,
        "no_of_at": num_at,
        "no_of_comma": num_comma,
        "no_of_dollar": num_dollar,
        "no_of_semicolon": num_semicolon,
        "no_of_space": num_space,
        "no_of_ampersand": num_ampersand,
        "no_of_dots": num_dots,
        "no_of_equal": num_equal,
        "no_of_percent": num_percent,
        "no_of_underscore": num_underscores,
        "no_of_hyphen": num_hyphens,
        "no_of_questionmark": num_question,
        "no_of_colon": num_colon,
        "no_of_slashes_inpath": num_slashes_inpath,
        "has_asterisk": has_asterisk,
        "has_or": has_or,
        "has_embedded_url": has_embedded_url,
        "uses_https": is_https,
        "num_query_params": num_query_params,
        "numeric_proportion": round(digit_ratio, 4),
        "url_entropy": round(url_entropy, 4),
        "hostname_digit_ratio": round(hostname_digit_ratio, 4),
        "has_redirections": 1 if "//" in path else 0,
        "has_punycode": is_punycode,
        "count_www": count_www,
        "count_com": count_com,
        "url_has_high_risk_extension": has_high_risk_ext,
        "has_explicit_port": has_port,
        "total_words_url": total_words,
        "average_length_of_words": round(avg_word_len, 4),
        "longest_word_length": longest_word,
        "shortest_word_length": shortest_word,
        "presence_of_free_hosting": is_free_hosting,

        # Helper keys for XAI / Explainability engine & backward compatibility
        "is_https": is_https,
        "is_ip_address": is_ip,
        "is_punycode": is_punycode,
        "hostname_length": host_len,
        "path_length": path_len,
        "query_length": query_len,
        "is_suspicious_port": is_suspicious_port,
        "suspicious_tld_indicator": 1 if tld in SUSPICIOUS_TLDS else 0,
        "suspicious_keywords_count": sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url_lower),
        "brand_in_subdomain_or_path": 1 if (brand_sub or brand_path_query) else 0,
        "excessive_percent_encoding": 1 if num_percent >= 3 else 0,
        "has_at_symbol": 1 if num_at > 0 else 0,
        "is_shortened_url": is_shortened,
        "base_domain": base_domain,
        "hostname": hostname
    }
