import re
from typing import Dict, Any, List, Set, Tuple
from urllib.parse import urlparse
from bs4 import BeautifulSoup, Comment
from ml.email.schema import EmailRecord
from ml.email.domain_analyzer import get_organizational_domain, classify_domain_relation

URL_REGEX = re.compile(r'https?://[^\s<>"]+|www\.[^\s<>"]+')

# Zero-width & invisible Unicode characters
ZERO_WIDTH_CHARS = {'\u200b', '\u200c', '\u200d', '\ufeff', '\u2060', '\u180e', '\u034f', '\u200e', '\u200f', '\u202a', '\u202b', '\u202c', '\u202d', '\u202e'}

# Phishing target brand lures for hidden text obfuscation checks
PHISHING_KEYWORDS = ['password', 'login', 'verify', 'credential', 'suspend', 'banking', 'wallet', 'ssn', 'tax', 'invoice', 'authenticate']


def analyze_invisible_characters(text: str) -> Dict[str, Any]:
    """
    Analyzes zero-width and invisible character occurrences in email content.
    Differentiates standard marketing preheader spacing from malicious evasion obfuscation.
    """
    if not text:
        return {
            "zero_width_char_count": 0,
            "invisible_char_ratio": 0.0,
            "is_malicious_obfuscation": False,
            "obfuscation_type": "NONE"
        }

    total_chars = len(text)
    zero_width_count = sum(1 for c in text if c in ZERO_WIDTH_CHARS)
    ratio = zero_width_count / max(total_chars, 1)

    # Check if zero-width characters are intermingled inside words to split phishing keywords
    # E.g., 'p\u200ba\u200by\u200bp\u200ba\u200bl' -> stripped: 'paypal'
    cleaned_text = "".join(c for c in text if c not in ZERO_WIDTH_CHARS).lower()
    
    keyword_in_raw = any(kw in text.lower() for kw in PHISHING_KEYWORDS)
    keyword_in_cleaned = any(kw in cleaned_text for kw in PHISHING_KEYWORDS)

    is_obfuscating_phish = (not keyword_in_raw) and keyword_in_cleaned and (zero_width_count > 0)

    obfuscation_type = "NONE"
    if is_obfuscating_phish:
        obfuscation_type = "MALICIOUS_KEYWORD_SPLITTING"
    elif zero_width_count > 10:
        obfuscation_type = "MARKETING_PREHEADER_SPACING"

    return {
        "zero_width_char_count": zero_width_count,
        "invisible_char_ratio": round(ratio, 4),
        "is_malicious_obfuscation": is_obfuscating_phish,
        "obfuscation_type": obfuscation_type
    }


def extract_html_features(record: EmailRecord) -> Dict[str, Any]:
    """
    Extracts static security and forensic features from the HTML payload of an email.
    Evaluates links, hidden DOM categories, forms, iframes, and anchor domain mismatches.
    """
    html = record.html or ""
    sender_domain = record.from_domain.lower()
    sender_org = get_organizational_domain(sender_domain)

    # Analyze invisible characters across plain text and HTML
    combined_raw_text = (record.plain_text or "") + " " + html
    invis_metrics = analyze_invisible_characters(combined_raw_text)

    if not html:
        return {
            "html_present": 0,
            "html_link_count": 0,
            "html_external_link_ratio": 0.0,
            "html_hidden_element_count": 0,
            "html_iframe_count": 0,
            "html_form_count": 0,
            "html_external_form_action": 0,
            "html_anchor_href_mismatch_count": 0,
            "html_script_tag_count": 0,
            "html_tracking_pixel_count": 0,
            "html_image_count": 0,
            "zero_width_char_count": invis_metrics["zero_width_char_count"],
            "invisible_char_ratio": invis_metrics["invisible_char_ratio"],
            "has_hidden_preheader": 0,
            "has_hidden_form": 0,
            "has_hidden_script": 0,
            "dom_categories": []
        }

    try:
        soup = BeautifulSoup(html, "html.parser")
    except Exception:
        soup = None

    if not soup:
        return {
            "html_present": 1,
            "html_link_count": 0,
            "html_external_link_ratio": 0.0,
            "html_hidden_element_count": 0,
            "html_iframe_count": 0,
            "html_form_count": 0,
            "html_external_form_action": 0,
            "html_anchor_href_mismatch_count": 0,
            "html_script_tag_count": 0,
            "html_tracking_pixel_count": 0,
            "html_image_count": 0,
            "zero_width_char_count": invis_metrics["zero_width_char_count"],
            "invisible_char_ratio": invis_metrics["invisible_char_ratio"],
            "has_hidden_preheader": 0,
            "has_hidden_form": 0,
            "has_hidden_script": 0,
            "dom_categories": []
        }

    # Links analysis with organizational domain alignment
    links = soup.find_all("a", href=True)
    link_count = len(links)
    external_links = 0
    anchor_mismatch_count = 0

    for a in links:
        href = a.get("href", "").strip()
        link_org = get_organizational_domain(href)
        
        if sender_org and link_org and link_org != sender_org:
            external_links += 1

        # Check anchor text domain vs href destination domain
        anchor_text = a.get_text(strip=True)
        if anchor_text:
            text_urls = URL_REGEX.findall(anchor_text)
            for tu in text_urls:
                text_org = get_organizational_domain(tu)
                if text_org and link_org and text_org != link_org:
                    anchor_mismatch_count += 1

    external_link_ratio = external_links / max(link_count, 1) if link_count > 0 else 0.0

    # Categorized Hidden elements detection
    hidden_count = 0
    has_hidden_preheader = 0
    has_hidden_form = 0
    has_hidden_script = 0
    dom_categories: List[str] = []

    hidden_elements = []
    for el in soup.find_all(attrs={"style": True}):
        style = el.get("style", "").lower()
        if any(h in style for h in ["display:none", "display: none", "visibility:hidden", "visibility: hidden", "opacity:0", "font-size:0", "max-height:0", "mso-hide:all"]):
            hidden_elements.append((el, style))

    for el in soup.find_all(attrs={"hidden": True}):
        hidden_elements.append((el, "hidden"))

    for el, style in hidden_elements:
        hidden_count += 1
        el_text = el.get_text(strip=True)
        el_tag = el.name.lower() if el.name else ""

        classes_list = el.get("class", []) or []
        if isinstance(classes_list, str):
            classes_list = [classes_list]
        classes_and_id = " ".join(classes_list + ([el.get("id")] if el.get("id") else [])).lower()
        combined_attrs = f"{style} {classes_and_id}"

        # Check for hidden preheader
        is_preheader_style = any(kw in combined_attrs for kw in ["preview", "preheader", "snippet", "mso-hide", "display:none", "display: none", "font-size:0", "font-size: 0", "max-height:0", "max-height: 0", "opacity:0", "color:transparent"])
        
        if len(el_text) < 300 and not el.find(["form", "input", "script"]) and is_preheader_style:
            has_hidden_preheader = 1
            if "HIDDEN_PREHEADER" not in dom_categories:
                dom_categories.append("HIDDEN_PREHEADER")
        elif el_tag == "form" or el.find("form") or el.find("input", attrs={"type": "password"}):
            has_hidden_form = 1
            if "HIDDEN_FORM" not in dom_categories:
                dom_categories.append("HIDDEN_FORM")
        elif el_tag == "script" or el.find("script"):
            has_hidden_script = 1
            if "HIDDEN_SCRIPT" not in dom_categories:
                dom_categories.append("HIDDEN_SCRIPT")
        elif "mso-hide" in style or any("hide" in str(c).lower() for c in classes_list):
            if "RESPONSIVE_HIDDEN_ELEMENT" not in dom_categories:
                dom_categories.append("RESPONSIVE_HIDDEN_ELEMENT")
        elif el.find("a"):
            if "HIDDEN_LINK" not in dom_categories:
                dom_categories.append("HIDDEN_LINK")
        else:
            if "HIDDEN_TEXT" not in dom_categories:
                dom_categories.append("HIDDEN_TEXT")

    # Forms & iframes
    iframes = len(soup.find_all("iframe"))
    forms = soup.find_all("form")
    form_count = len(forms)
    external_form_action = 0

    for f in forms:
        action = f.get("action", "").strip()
        action_org = get_organizational_domain(action)
        if action_org and sender_org and action_org != sender_org:
            external_form_action += 1

    # Scripts
    scripts = len(soup.find_all("script"))
    if scripts > 0 and "SCRIPT_TAGS" not in dom_categories:
        dom_categories.append("SCRIPT_TAGS")

    # Images & tracking pixels
    images = soup.find_all("img")
    image_count = len(images)
    tracking_pixel_count = 0
    for img in images:
        w = str(img.get("width", "")).strip()
        h = str(img.get("height", "")).strip()
        src = img.get("src", "").lower()
        if (w in ("0", "1") and h in ("0", "1")) or any(t in src for t in ["pixel", "open", "track", "beacon"]):
            tracking_pixel_count += 1
            if "TRACKING_PIXEL" not in dom_categories:
                dom_categories.append("TRACKING_PIXEL")

    return {
        "html_present": 1,
        "html_link_count": min(link_count, 50),
        "html_external_link_ratio": round(external_link_ratio, 4),
        "html_hidden_element_count": min(hidden_count, 20),
        "html_iframe_count": min(iframes, 10),
        "html_form_count": min(form_count, 10),
        "html_external_form_action": min(external_form_action, 10),
        "html_anchor_href_mismatch_count": min(anchor_mismatch_count, 20),
        "html_script_tag_count": min(scripts, 10),
        "html_tracking_pixel_count": min(tracking_pixel_count, 10),
        "html_image_count": min(image_count, 50),
        "zero_width_char_count": invis_metrics["zero_width_char_count"],
        "invisible_char_ratio": invis_metrics["invisible_char_ratio"],
        "has_hidden_preheader": has_hidden_preheader,
        "has_hidden_form": has_hidden_form,
        "has_hidden_script": has_hidden_script,
        "dom_categories": dom_categories
    }
