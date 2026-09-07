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
    Parses HTML statically and extracts comprehensive DOM, structural, form, script,
    iframe, and resource features.
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

    # General page metrics
    html_size = len(html_content)
    title_tag = soup.find("title")
    title_text = title_tag.get_text().strip() if title_tag else ""
    title_len = len(title_text)
    has_title = 1 if title_text else 0
    title_domain_sim = calculate_jaccard_similarity(title_text, page_base_domain)

    # Visible text
    for invisible in soup(["script", "style", "meta", "noscript"]):
        invisible.decompose()
    visible_text = soup.get_text()
    visible_text_clean = " ".join(visible_text.split())
    visible_text_len = len(visible_text_clean)
    text_to_html_ratio = visible_text_len / max(html_size, 1)

    # Re-parse fresh soup for link/tag inspection since we decomposed tags above
    try:
        fresh_soup = BeautifulSoup(html_content, "html.parser")
    except Exception:
        fresh_soup = BeautifulSoup("", "html.parser")

    # Link analysis
    all_links = fresh_soup.find_all("a")
    total_links = len(all_links)
    internal_links = 0
    external_links = 0
    empty_links = 0

    for a in all_links:
        href = (a.get("href") or "").strip()
        if not href or href in ("#", "javascript:void(0);", "javascript:;"):
            empty_links += 1
            continue
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

    external_link_ratio = external_links / max(total_links, 1)
    empty_link_ratio = empty_links / max(total_links, 1)

    # Image analysis
    images = fresh_soup.find_all("img")
    total_images = len(images)
    external_images = 0
    for img in images:
        src = (img.get("src") or "").strip()
        if src.startswith(("http://", "https://", "//")):
            resolved_src = urljoin(page_url, src)
            i_host = urlparse(resolved_src).hostname or ""
            i_base = extract_base_domain(i_host)
            if i_base and i_base != page_base_domain:
                external_images += 1
    external_img_ratio = external_images / max(total_images, 1)

    # Meta tags & refresh
    meta_tags = fresh_soup.find_all("meta")
    has_meta_refresh = 0
    for m in meta_tags:
        http_equiv = (m.get("http-equiv") or "").lower()
        if http_equiv == "refresh":
            has_meta_refresh = 1
            break

    # Iframes
    iframes = fresh_soup.find_all("iframe")
    total_iframes = len(iframes)
    external_iframes = 0
    hidden_iframes = 0

    for ifr in iframes:
        src = (ifr.get("src") or "").strip()
        style = (ifr.get("style") or "").lower()
        width = str(ifr.get("width") or "").strip()
        height = str(ifr.get("height") or "").strip()

        if "display:none" in style or "visibility:hidden" in style or width in ("0", "0px") or height in ("0", "0px"):
            hidden_iframes += 1

        if src.startswith(("http://", "https://", "//")):
            resolved_ifr = urljoin(page_url, src)
            ifr_host = urlparse(resolved_ifr).hostname or ""
            ifr_base = extract_base_domain(ifr_host)
            if ifr_base and ifr_base != page_base_domain:
                external_iframes += 1

    # Extract component features
    form_data = extract_form_features(fresh_soup, page_url)
    script_data = extract_script_features(fresh_soup, page_url)
    download_data = extract_download_features(fresh_soup, page_url)

    # Combined page feature dictionary
    features = {
        "html_size": html_size,
        "has_title": has_title,
        "title_length": title_len,
        "title_domain_similarity": round(title_domain_sim, 4),
        "visible_text_length": visible_text_len,
        "text_to_html_ratio": round(text_to_html_ratio, 4),
        "num_links": total_links,
        "num_internal_links": internal_links,
        "num_external_links": external_links,
        "external_link_ratio": round(external_link_ratio, 4),
        "empty_link_ratio": round(empty_link_ratio, 4),
        "num_images": total_images,
        "num_external_images": external_images,
        "external_image_ratio": round(external_img_ratio, 4),
        "num_meta_tags": len(meta_tags),
        "has_meta_refresh": has_meta_refresh,
        "num_iframes": total_iframes,
        "num_external_iframes": external_iframes,
        "has_hidden_iframe": 1 if hidden_iframes > 0 else 0,
    }

    # Merge form, script, download features
    features.update(form_data)
    features.update(script_data)
    features.update(download_data)

    return features
