import email
from email import policy
from email.message import EmailMessage
from email.utils import parseaddr
import re
import os
from typing import Union, Tuple, List, Optional
from bs4 import BeautifulSoup
from urllib.parse import urlparse

from ml.email.schema import EmailRecord, AttachmentMetadata
from ml.email.config import (
    MAX_BODY_TEXT_LENGTH,
    MAX_URLS_TO_ANALYZE,
    MAX_ATTACHMENTS,
    EXECUTABLE_EXTENSIONS,
    MACRO_EXTENSIONS,
    ARCHIVE_EXTENSIONS,
)

# Robust URL regex pattern
URL_REGEX = re.compile(
    r'(?:http[s]?://|www\.)(?:[a-zA-Z0-9$-_@.&+!*"(),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
)

DOUBLE_EXT_REGEX = re.compile(
    r'\.(pdf|doc|docx|xls|xlsx|jpg|png|txt|mp3|zip)\.(exe|scr|bat|cmd|vbs|js|ps1|hta|msi|cpl|com|pif)$',
    re.IGNORECASE
)


def extract_domain_from_email_addr(email_str: str) -> str:
    """Extracts cleaned base domain from email address (e.g. user@sub.example.com -> sub.example.com)."""
    if not email_str:
        return ""
    _, addr = parseaddr(email_str)
    if "@" in addr:
        return addr.split("@")[-1].lower().strip().rstrip(">")
    return ""


def clean_html_to_plain_text(html_content: str) -> Tuple[str, List[str]]:
    """
    Safely converts HTML content to clean plaintext and extracts all href URLs.
    Never executes or evaluates scripts/DOM.
    """
    if not html_content:
        return "", []

    extracted_urls = []
    try:
        soup = BeautifulSoup(html_content, "html.parser")
        
        # Collect hrefs
        for a in soup.find_all("a", href=True):
            href = a.get("href", "").strip()
            if href and (href.startswith("http://") or href.startswith("https://") or href.startswith("www.")):
                extracted_urls.append(href)

        # Collect image sources
        for img in soup.find_all("img", src=True):
            src = img.get("src", "").strip()
            if src and (src.startswith("http://") or src.startswith("https://")):
                extracted_urls.append(src)

        # Strip scripts and styles
        for tag in soup(["script", "style", "head", "meta", "noscript"]):
            tag.decompose()

        plain_text = soup.get_text(separator=" ", strip=True)
        return plain_text[:MAX_BODY_TEXT_LENGTH], extracted_urls
    except Exception:
        # Fallback regex strip
        text = re.sub(r'<[^>]+>', ' ', html_content)
        return text[:MAX_BODY_TEXT_LENGTH], extracted_urls


def parse_raw_eml(eml_bytes_or_str: Union[bytes, str], source_dataset: str = "live_stream") -> EmailRecord:
    """
    Safely parses an RFC-5322 MIME email payload into a normalized EmailRecord.
    """
    if isinstance(eml_bytes_or_str, str):
        msg = email.message_from_string(eml_bytes_or_str, policy=policy.default)
    else:
        msg = email.message_from_bytes(eml_bytes_or_str, policy=policy.default)

    subject = str(msg.get("Subject", "") or "")
    from_raw = str(msg.get("From", "") or "")
    reply_to_raw = str(msg.get("Reply-To", "") or "")
    return_path_raw = str(msg.get("Return-Path", "") or "")
    message_id = str(msg.get("Message-ID", "") or "")
    date_str = str(msg.get("Date", "") or "")
    auth_results = str(msg.get("Authentication-Results", "") or "")
    received_spf = str(msg.get("Received-SPF", "") or "")

    # Collect Received headers
    received_headers = [str(h) for h in msg.get_all("Received", [])]

    # Domain extraction
    from_domain = extract_domain_from_email_addr(from_raw)
    reply_to_domain = extract_domain_from_email_addr(reply_to_raw)
    return_path_domain = extract_domain_from_email_addr(return_path_raw)

    # Authentication verdict extraction
    spf_verdict = "none"
    combined_auth = (auth_results + " " + received_spf).lower()
    if "spf=pass" in combined_auth or "pass" in received_spf.lower():
        spf_verdict = "pass"
    elif "spf=fail" in combined_auth or "fail" in received_spf.lower() or "softfail" in combined_auth:
        spf_verdict = "fail"
    elif "spf=neutral" in combined_auth:
        spf_verdict = "neutral"

    dkim_verdict = "none"
    if "dkim=pass" in combined_auth or "dkim: pass" in combined_auth:
        dkim_verdict = "pass"
    elif "dkim=fail" in combined_auth or "dkim: fail" in combined_auth:
        dkim_verdict = "fail"

    dmarc_verdict = "none"
    if "dmarc=pass" in combined_auth:
        dmarc_verdict = "pass"
    elif "dmarc=fail" in combined_auth:
        dmarc_verdict = "fail"

    # Extract Body and Attachments safely
    plain_text_parts = []
    html_parts = []
    attachments: List[AttachmentMetadata] = []
    urls: List[str] = []

    if msg.is_multipart():
        for part in msg.walk():
            content_disposition = str(part.get("Content-Disposition", "") or "")
            content_type = part.get_content_type()
            filename = part.get_filename() or ""

            if "attachment" in content_disposition.lower() or (filename and content_type != "text/plain" and content_type != "text/html"):
                # Safe static metadata extraction
                _, ext = os.path.splitext(filename.lower())
                raw_payload = part.get_payload(decode=True)
                size_bytes = len(raw_payload) if raw_payload else 0
                
                is_exec = ext in EXECUTABLE_EXTENSIONS
                is_macro = ext in MACRO_EXTENSIONS
                is_archive = ext in ARCHIVE_EXTENSIONS
                is_double_ext = bool(DOUBLE_EXT_REGEX.search(filename))

                if is_double_ext:
                    is_exec = True

                if len(attachments) < MAX_ATTACHMENTS:
                    attachments.append(AttachmentMetadata(
                        filename=filename[:100],
                        extension=ext,
                        mime_type=content_type,
                        size_bytes=size_bytes,
                        is_executable=is_exec,
                        is_macro=is_macro,
                        is_archive=is_archive,
                        is_double_extension=is_double_ext
                    ))
            elif content_type == "text/plain":
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        charset = part.get_content_charset() or "utf-8"
                        text = payload.decode(charset, errors="ignore")
                        plain_text_parts.append(text)
                except Exception:
                    pass
            elif content_type == "text/html":
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        charset = part.get_content_charset() or "utf-8"
                        html_text = payload.decode(charset, errors="ignore")
                        html_parts.append(html_text)
                except Exception:
                    pass
    else:
        # Non-multipart
        content_type = msg.get_content_type()
        try:
            payload = msg.get_payload(decode=True)
            if payload:
                charset = msg.get_content_charset() or "utf-8"
                decoded_str = payload.decode(charset, errors="ignore")
                if content_type == "text/html" or ("<html" in decoded_str.lower() and "</" in decoded_str.lower()):
                    html_parts.append(decoded_str)
                else:
                    plain_text_parts.append(decoded_str)
        except Exception:
            pass

    full_plain = "\n".join(plain_text_parts)[:MAX_BODY_TEXT_LENGTH]
    full_html = "\n".join(html_parts)[:MAX_BODY_TEXT_LENGTH]

    # Extract URLs from HTML
    html_plain, html_urls = clean_html_to_plain_text(full_html)
    urls.extend(html_urls)
    clickable_href_occurrences = []
    if full_html:
        try:
            soup = BeautifulSoup(full_html, "html.parser")
            clickable_href_occurrences = [
                a.get("href", "").strip()
                for a in soup.find_all("a", href=True)
                if a.get("href", "").strip().startswith(("http://", "https://", "www."))
            ]
        except Exception:
            pass

    # If plain text was empty but HTML existed, use the stripped text
    if not full_plain and html_plain:
        full_plain = html_plain

    # Extract URLs from plaintext
    plain_urls = URL_REGEX.findall(full_plain)
    for u in plain_urls:
        if u.startswith("www."):
            u = "http://" + u
        urls.append(u)

    # Preserve source occurrences for reporting, then make the bounded unique
    # set used by the feature/model pipeline.
    url_occurrences = []
    seen_urls = set()
    cleaned_urls = []
    for u in urls:
        clean_u = u.strip().rstrip(".,;)>\"'")
        if clean_u:
            url_occurrences.append(clean_u)
        if clean_u and clean_u not in seen_urls:
            seen_urls.add(clean_u)
            cleaned_urls.append(clean_u)
        if len(cleaned_urls) >= MAX_URLS_TO_ANALYZE:
            break

    return EmailRecord(
        id=message_id or "",
        source_dataset=source_dataset,
        label="unknown",
        subject=subject,
        plain_text=full_plain,
        html=full_html,
        from_address=from_raw,
        from_domain=from_domain,
        reply_to=reply_to_raw,
        reply_to_domain=reply_to_domain,
        return_path=return_path_raw,
        return_path_domain=return_path_domain,
        received_headers=received_headers,
        authentication_results=auth_results,
        spf_verdict=spf_verdict,
        dkim_verdict=dkim_verdict,
        dmarc_verdict=dmarc_verdict,
        message_id=message_id,
        date=date_str,
        urls=cleaned_urls,
        url_occurrences=url_occurrences,
        clickable_href_occurrences=clickable_href_occurrences,
        attachments=attachments
    )


def parse_pasted_email(sender: str, body_or_headers: str, subject: str = "") -> EmailRecord:
    """
    Parses pasted email text (which may contain raw RFC headers or just sender + body text).
    """
    body_stripped = body_or_headers.strip()
    
    # Check if the pasted text has standard RFC-822 headers at the top
    if re.search(r'^(From|Subject|Received|Date|To|Message-ID|Return-Path):', body_stripped, re.MULTILINE | re.IGNORECASE):
        # Parse as full RFC message
        parsed = parse_raw_eml(body_stripped, source_dataset="pasted_text")
        if not parsed.from_address and sender:
            parsed.from_address = sender
            parsed.from_domain = extract_domain_from_email_addr(sender)
        if subject and not parsed.subject:
            parsed.subject = subject
        return parsed

    # Simple text input with separate sender and body
    from_domain = extract_domain_from_email_addr(sender)
    
    # Extract URLs from body
    urls = []
    url_occurrences = []
    for u in URL_REGEX.findall(body_stripped):
        if u.startswith("www."):
            u = "http://" + u
        clean_u = u.strip().rstrip(".,;)>\"'")
        if clean_u:
            url_occurrences.append(clean_u)
        if clean_u not in urls:
            urls.append(clean_u)
        if len(urls) >= MAX_URLS_TO_ANALYZE:
            break

    return EmailRecord(
        id="",
        source_dataset="pasted_text",
        label="unknown",
        subject=subject,
        plain_text=body_stripped[:MAX_BODY_TEXT_LENGTH],
        html="",
        from_address=sender,
        from_domain=from_domain,
        reply_to="",
        reply_to_domain="",
        return_path="",
        return_path_domain="",
        received_headers=[],
        authentication_results="",
        spf_verdict="none",
        dkim_verdict="none",
        dmarc_verdict="none",
        message_id="",
        date="",
        urls=urls,
        url_occurrences=url_occurrences,
        clickable_href_occurrences=[],
        attachments=[]
    )
