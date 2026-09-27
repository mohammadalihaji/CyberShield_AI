from typing import Dict, Any
from ml.email.schema import EmailRecord


def extract_attachment_features(record: EmailRecord) -> Dict[str, Any]:
    """
    Extracts static, non-executing metadata features from email attachments.
    """
    attachments = record.attachments or []
    count = len(attachments)

    has_attach = 1 if count > 0 else 0
    has_exec = 1 if any(a.is_executable for a in attachments) else 0
    has_macro = 1 if any(a.is_macro for a in attachments) else 0
    has_archive = 1 if any(a.is_archive for a in attachments) else 0
    has_double_ext = 1 if any(a.is_double_extension for a in attachments) else 0

    total_size_bytes = sum(a.size_bytes for a in attachments)
    total_size_kb = total_size_bytes / 1024.0

    return {
        "attachment_count": min(count, 20),
        "has_attachments": has_attach,
        "has_executable_attachment": has_exec,
        "has_macro_attachment": has_macro,
        "has_archive_attachment": has_archive,
        "has_double_extension_attachment": has_double_ext,
        "total_attachment_size_kb": round(min(total_size_kb, 50000.0), 2)
    }
