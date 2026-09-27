from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional
import hashlib
import json

@dataclass
class AttachmentMetadata:
    """Safe metadata extracted from an email attachment without executing it."""
    filename: str
    extension: str
    mime_type: str
    size_bytes: int = 0
    is_executable: bool = False
    is_macro: bool = False
    is_archive: bool = False
    is_double_extension: bool = False


@dataclass
class EmailRecord:
    """
    Standardized, normalized email representation across all ingestion pipelines
    (Enron, SpamAssassin, MeAJOR, TREC, and live API .eml/pasted streams).
    """
    id: str
    source_dataset: str
    label: str  # 'ham', 'spam', 'phishing', or 'unknown'
    subject: str = ""
    plain_text: str = ""
    html: str = ""
    from_address: str = ""
    from_domain: str = ""
    reply_to: str = ""
    reply_to_domain: str = ""
    return_path: str = ""
    return_path_domain: str = ""
    received_headers: List[str] = field(default_factory=list)
    authentication_results: str = ""
    spf_verdict: str = "none"       # pass, fail, softfail, neutral, none
    dkim_verdict: str = "none"      # pass, fail, none
    dmarc_verdict: str = "none"     # pass, fail, none
    message_id: str = ""
    date: str = ""
    urls: List[str] = field(default_factory=list)
    # Source occurrences before parser deduplication. `urls` is the unique,
    # bounded analysis set; occurrences are retained for audit evidence.
    url_occurrences: List[str] = field(default_factory=list)
    # Anchor hrefs only (excluding image/src and plaintext URL occurrences).
    clickable_href_occurrences: List[str] = field(default_factory=list)
    attachments: List[AttachmentMetadata] = field(default_factory=list)
    raw_email_hash: str = ""

    def __post_init__(self):
        if not self.raw_email_hash:
            content_to_hash = f"{self.from_address}|{self.subject}|{self.plain_text[:500]}".encode('utf-8', errors='ignore')
            self.raw_email_hash = hashlib.sha256(content_to_hash).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EmailRecord":
        attach_raw = data.get("attachments", [])
        attachments = []
        for a in attach_raw:
            if isinstance(a, dict):
                attachments.append(AttachmentMetadata(**a))
            elif isinstance(a, AttachmentMetadata):
                attachments.append(a)
        
        data_copy = dict(data)
        data_copy["attachments"] = attachments
        return cls(**data_copy)
