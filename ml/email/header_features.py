import re
from typing import Dict, Any
from ml.email.schema import EmailRecord
from ml.email.config import SUSPICIOUS_EMAIL_KEYWORDS

from ml.email.domain_analyzer import classify_domain_relation, DomainRelation

FREE_EMAIL_PROVIDERS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com",
    "icloud.com", "protonmail.com", "mail.com", "zoho.com", "yandex.com"
}


def extract_header_features(record: EmailRecord) -> Dict[str, Any]:
    """
    Extracts structured, deterministic header and authentication features from an EmailRecord.
    Utilizes organizational domain relationship classification instead of naive string matching.
    """
    from_dom = record.from_domain.lower()
    reply_dom = record.reply_to_domain.lower()
    return_dom = record.return_path_domain.lower()

    reply_rel = classify_domain_relation(from_dom, reply_dom) if (from_dom and reply_dom) else None
    return_rel = classify_domain_relation(from_dom, return_dom) if (from_dom and return_dom) else None

    # Mismatch is 1 only when domains are genuinely unrelated organizations
    from_reply_to_mismatch = 1 if (reply_rel and not reply_rel["is_aligned"]) else 0
    from_return_path_mismatch = 1 if (return_rel and not return_rel["is_aligned"]) else 0

    # Authentication indicators
    spf_pass = 1 if record.spf_verdict == "pass" else 0
    spf_fail = 1 if record.spf_verdict == "fail" else 0
    spf_missing = 1 if record.spf_verdict in ("none", "") else 0

    dkim_pass = 1 if record.dkim_verdict == "pass" else 0
    dkim_fail = 1 if record.dkim_verdict == "fail" else 0
    dkim_missing = 1 if record.dkim_verdict in ("none", "") else 0

    dmarc_pass = 1 if record.dmarc_verdict == "pass" else 0
    dmarc_fail = 1 if record.dmarc_verdict == "fail" else 0
    dmarc_missing = 1 if record.dmarc_verdict in ("none", "") else 0

    auth_failure_count = spf_fail + dkim_fail + dmarc_fail
    auth_pass_count = spf_pass + dkim_pass + dmarc_pass

    received_hops = len(record.received_headers)

    # Message-ID domain matching
    msg_id_match = 0
    if record.message_id and from_dom:
        if from_dom in record.message_id.lower():
            msg_id_match = 1

    # Free email provider used as sender
    is_free_provider_sender = 1 if from_dom in FREE_EMAIL_PROVIDERS else 0

    # Subject line features
    subj = record.subject or ""
    subj_len = len(subj)
    subj_upper_count = sum(1 for c in subj if c.isupper())
    subj_upper_ratio = subj_upper_count / max(subj_len, 1)
    
    subj_lower = subj.lower()
    subj_urgency = 1 if any(kw in subj_lower for kw in SUSPICIOUS_EMAIL_KEYWORDS[:12]) else 0
    subj_has_re_fwd = 1 if re.match(r'^(re|fwd|fw):\s*', subj_lower) else 0

    # Header anomalies count
    anomaly_count = from_reply_to_mismatch + from_return_path_mismatch + (1 if received_hops > 10 else 0)

    return {
        "from_reply_to_mismatch": from_reply_to_mismatch,
        "from_return_path_mismatch": from_return_path_mismatch,
        "spf_pass": spf_pass,
        "spf_fail": spf_fail,
        "spf_missing": spf_missing,
        "dkim_pass": dkim_pass,
        "dkim_fail": dkim_fail,
        "dkim_missing": dkim_missing,
        "dmarc_pass": dmarc_pass,
        "dmarc_fail": dmarc_fail,
        "dmarc_missing": dmarc_missing,
        "auth_failure_count": auth_failure_count,
        "auth_pass_count": auth_pass_count,
        "received_hop_count": min(received_hops, 20),
        "message_id_domain_match": msg_id_match,
        "is_free_provider_sender": is_free_provider_sender,
        "subject_length": subj_len,
        "subject_uppercase_ratio": round(subj_upper_ratio, 4),
        "subject_has_urgency": subj_urgency,
        "subject_has_re_fwd": subj_has_re_fwd,
        "header_anomaly_count": anomaly_count
    }
