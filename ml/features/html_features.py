import re
from urllib.parse import urlparse, urljoin
from typing import Dict, Any, List
from bs4 import BeautifulSoup
from ml.features.url_features import extract_base_domain
from ml.features.form_features import extract_form_features
from ml.features.script_features import extract_script_features
from ml.features.download_features import extract_download_features


def calculate_jaccard_similarity(str1: str, str2: str) -> float:
    """Calculates word-token Jaccard similarity between two strings."""
    if not str1 or not str2:
        return 0.0
    tokens1 = set(re.findall(r"\w+", str1.lower()))
    tokens2 = set(re.findall(r"\w+", str2.lower()))
    if not tokens1 or not tokens2:
        return 0.0
    intersection = len(tokens1 & tokens2)
    union = len(tokens1 | tokens2)
    return intersection / union if union > 0 else 0.0


def extract_html_features(html_content: str, page_url: str) -> Dict[str, Any]:
    """
    Parses HTML statically and extracts both CompPhish V4 (23 features)
    and granular form, script, and DOM telemetry.
    """
    if not html_content:
        html_content = ""
    
    if not page_url:
        page_url = "https://unknown.domain"

    page_host = urlparse(page_url).hostname or ""
    page_base_domain = extract_base_domain(page_host)

    try:
        soup = BeautifulSoup(html_content, "html.parser")
    except Exception:
        soup = BeautifulSoup("", "html.parser")

    # Title & Metadata
    title_tag = soup.find("title")
    title_text = title_tag.get_text().strip() if title_tag else ""
    has_title = 1 if title_text else 0
    has_missing_title = 0 if has_title else 1
    title_domain_sim = calculate_jaccard_similarity(title_text, page_base_domain)
    title_mismatch = 1 if (has_title and title_domain_sim < 0.15) else 0

    # Links
    all_links = soup.find_all("a")
    total_links = len(all_links)
    internal_links = 0
    external_links = 0
    empty_links = 0
    null_links = 0
    selfref_links = 0
    inline_handlers = 0

    for a in all_links:
        href = (a.get("href") or "").strip()
        
        # Check inline event handlers
        if any(a.has_attr(attr) for attr in ["onclick", "onmouseover", "onmouseout", "onload"]):
            inline_handlers += 1

        if not href or href in ("#", "javascript:void(0);", "javascript:;"):
            empty_links += 1
            null_links += 1
            continue
        
        if href == page_url or href == "./" or href == "/":
            selfref_links += 1

        if href.startswith(("/", "./", "../", "#")) or not href.startswith(("http://", "https://", "//")):
            internal_links += 1
        else:
            resolved_href = urljoin(page_url, href)
            h_host = urlparse(resolved_href).hostname or ""
            h_base = extract_base_domain(h_host)
            if h_base and h_base == page_base_domain:
                internal_links += 1
            else:
                external_links += 1

    empty_to_ext_ratio = empty_links / max(external_links, 1)

    # Images
    images = soup.find_all("img")
    total_images = len(images)

    # Hidden elements
    hidden_elements = 0
    for el in soup.find_all(True):
        style = (el.get("style") or "").lower()
        if "display:none" in style or "visibility:hidden" in style:
            hidden_elements += 1
    has_hidden_elements = 1 if hidden_elements > 0 else 0

    # Extract component features
    form_data = extract_form_features(soup, page_url)
    script_data = extract_script_features(soup, page_url)
    download_data = extract_download_features(soup, page_url)

    # Script external domain check
    script_ext = 1 if script_data.get("num_external_scripts", 0) > 0 else 0
    suspicious_inline = 1 if (script_data.get("has_eval", 0) or script_data.get("has_document_write", 0) or script_data.get("has_event_tampering", 0)) else 0

    # Risky extensions
    risky_ext_html = download_data.get("has_executable_download", 0)
    has_inline_events = 1 if inline_handlers > 0 else 0
    form_action_ext = form_data.get("has_external_form_submit", 0)

    # Combined dictionary containing CompPhish V4 23 features + granular findings
    features = {
        # CompPhish V4 exact feature schema (23 features)
        "no_of_forms": form_data.get("total_forms", 0),
        "no_of_Images": total_images,
        "no_of_hyperlinks": total_links,
        "no_of_external_links": external_links,
        "no_of_internal_links": internal_links,
        "no_of_null_links": null_links,
        "no_of_selfreference_links": selfref_links,
        "no_of_empty_links": empty_links,
        "EmptyToExternalLinksRatio": round(empty_to_ext_ratio, 4),
        "Risky_extensions_In_Html": risky_ext_html,
        "presence_of_shorten_url_html": 0,
        "hidden_elements_html": has_hidden_elements,
        "Script_loaded_from_ext_domain": script_ext,
        "suspicious_inline_js": suspicious_inline,
        "is_footer_mismatch": 0,
        "is_header_mismatch": 0,
        "is_copyright_mismatch": 0,
        "is_socials_mismatch": 0,
        "is_favicon_mismatch": 0,
        "has_missing_title": has_missing_title,
        "title_mismatch_with_domain": title_mismatch,
        "has_inline_event_handlers": has_inline_events,
        "form_action_external": form_action_ext,

        # Granular properties for XAI Engine
        "html_size": len(html_content),
        "has_title": has_title,
        "title_length": len(title_text),
        "title_domain_similarity": round(title_domain_sim, 4),
        "num_links": total_links,
        "num_internal_links": internal_links,
        "num_external_links": external_links,
        "num_images": total_images,
        "has_hidden_iframe": 1 if soup.find("iframe", style=re.compile(r"display:\s*none|visibility:\s*hidden", re.I)) else 0
    }

    # Merge granular form, script, download items for Explainable AI
    features.update(form_data)
    features.update(script_data)
    features.update(download_data)

    return features
