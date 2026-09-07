import re
from typing import Dict, Any, List
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from ml.features.url_features import calculate_entropy, extract_base_domain

# Static JS pattern signatures
EVAL_PATTERN = re.compile(r"\b(window\.)?eval\s*\(", re.IGNORECASE)
FUNCTION_CTOR_PATTERN = re.compile(r"\bnew\s+Function\s*\(", re.IGNORECASE)
DOC_WRITE_PATTERN = re.compile(r"\bdocument\.(write|writeln)\s*\(", re.IGNORECASE)
UNESCAPE_PATTERN = re.compile(r"\b(window\.)?unescape\s*\(", re.IGNORECASE)
ATOB_PATTERN = re.compile(r"\b(window\.)?atob\s*\(", re.IGNORECASE)
COOKIE_PATTERN = re.compile(r"\bdocument\.cookie\b", re.IGNORECASE)
STORAGE_PATTERN = re.compile(r"\b(localStorage|sessionStorage)\b", re.IGNORECASE)
LOCATION_PATTERN = re.compile(r"\b(location\.href|location\.replace|location\.assign|window\.location)\b", re.IGNORECASE)
CONTEXT_MENU_DISABLE = re.compile(r"(oncontextmenu|preventDefault\(\)|event\.returnValue\s*=\s*false|return\s+false)", re.IGNORECASE)
BASE64_LONG_PATTERN = re.compile(r"['\"][A-Za-z0-9+/=]{40,}['\"]")


def extract_script_features(soup: BeautifulSoup, page_url: str) -> Dict[str, Any]:
    """
    Performs static script feature analysis on HTML.
    Does NOT execute JavaScript code.
    """
    if not page_url:
        page_url = "https://unknown.domain"
        
    page_host = urlparse(page_url).hostname or ""
    page_base_domain = extract_base_domain(page_host)

    scripts = soup.find_all("script") if soup else []
    total_scripts = len(scripts)

    inline_scripts: List[str] = []
    external_scripts: List[str] = []
    external_domains = set()

    for script in scripts:
        src = script.get("src")
        if src:
            resolved_src = urljoin(page_url, src)
            external_scripts.append(resolved_src)
            src_host = urlparse(resolved_src).hostname or ""
            src_base = extract_base_domain(src_host)
            if src_base and src_base != page_base_domain:
                external_domains.add(src_base)
        else:
            inline_text = script.string or script.get_text() or ""
            if inline_text.strip():
                inline_scripts.append(inline_text)

    num_inline = len(inline_scripts)
    num_external = len(external_scripts)
    external_script_ratio = num_external / max(total_scripts, 1)

    combined_inline = "\n".join(inline_scripts)
    total_script_length = len(combined_inline)
    max_script_length = max((len(s) for s in inline_scripts), default=0)

    # Suspicious pattern occurrences in inline scripts
    has_eval = 1 if EVAL_PATTERN.search(combined_inline) else 0
    has_function_ctor = 1 if FUNCTION_CTOR_PATTERN.search(combined_inline) else 0
    has_doc_write = 1 if DOC_WRITE_PATTERN.search(combined_inline) else 0
    has_unescape = 1 if UNESCAPE_PATTERN.search(combined_inline) else 0
    has_atob = 1 if ATOB_PATTERN.search(combined_inline) else 0
    has_cookie = 1 if COOKIE_PATTERN.search(combined_inline) else 0
    has_storage = 1 if STORAGE_PATTERN.search(combined_inline) else 0
    has_location_redirect = 1 if LOCATION_PATTERN.search(combined_inline) else 0
    has_tamper = 1 if CONTEXT_MENU_DISABLE.search(combined_inline) else 0
    has_base64 = 1 if BASE64_LONG_PATTERN.search(combined_inline) else 0

    script_entropy = calculate_entropy(combined_inline) if combined_inline else 0.0

    return {
        "num_scripts": total_scripts,
        "num_inline_scripts": num_inline,
        "num_external_scripts": num_external,
        "num_external_script_domains": len(external_domains),
        "external_script_ratio": round(external_script_ratio, 4),
        "total_script_length": total_script_length,
        "max_script_length": max_script_length,
        "script_entropy": round(script_entropy, 4),
        "has_eval": has_eval,
        "has_function_constructor": has_function_ctor,
        "has_document_write": has_doc_write,
        "has_unescape": has_unescape,
        "has_atob": has_atob,
        "has_cookie_access": has_cookie,
        "has_storage_access": has_storage,
        "has_window_location_redirect": has_location_redirect,
        "has_event_tampering": has_tamper,
        "has_base64_payload": has_base64
    }
