import re
import string
from typing import Dict, Any, List, Tuple
import numpy as np

from ml.email.schema import EmailRecord
from ml.email.config import SUSPICIOUS_EMAIL_KEYWORDS
from ml.email.header_features import extract_header_features
from ml.email.html_features import extract_html_features
from ml.email.attachment_features import extract_attachment_features
from ml.email.url_aggregator import EmailURLAggregator

# Ordered Structured Feature Names (Total: 44 structured features)
STRUCTURED_FEATURE_NAMES = [
    # 1. Header & Auth features (16)
    "from_reply_to_mismatch",
    "from_return_path_mismatch",
    "spf_pass",
    "spf_fail",
    "spf_missing",
    "dkim_pass",
    "dkim_fail",
    "dkim_missing",
    "dmarc_pass",
    "dmarc_fail",
    "dmarc_missing",
    "auth_failure_count",
    "auth_pass_count",
    "received_hop_count",
    "message_id_domain_match",
    "is_free_provider_sender",
    "header_anomaly_count",

    # 2. Text Statistics (10)
    "text_char_count",
    "text_word_count",
    "text_uppercase_ratio",
    "text_digit_ratio",
    "text_punct_ratio",
    "text_exclamation_count",
    "text_question_count",
    "text_suspicious_keyword_count",
    "text_html_to_text_ratio",
    "subject_length",
    "subject_uppercase_ratio",
    "subject_has_urgency",

    # 3. HTML DOM features (11)
    "html_present",
    "html_link_count",
    "html_external_link_ratio",
    "html_hidden_element_count",
    "html_iframe_count",
    "html_form_count",
    "html_external_form_action",
    "html_anchor_href_mismatch_count",
    "html_script_tag_count",
    "html_tracking_pixel_count",
    "html_image_count",

    # 4. Attachment features (7)
    "attachment_count",
    "has_attachments",
    "has_executable_attachment",
    "has_macro_attachment",
    "has_archive_attachment",
    "has_double_extension_attachment",
    "total_attachment_size_kb",

    # 5. URL Aggregate features (10)
    "email_url_count",
    "email_unique_domain_count",
    "email_suspicious_url_count",
    "email_max_url_risk",
    "email_avg_url_risk",
    "email_has_ip_url",
    "email_has_shortened_url",
    "email_has_punycode_url",
    "email_has_suspicious_tld_url",
    "email_has_brand_in_subdomain_url",
    "email_external_domain_url_ratio"
]


class EmailFeatureExtractor:
    """
    Consolidates header, HTML, attachment, text statistical, and URL security features
    into a standardized numeric feature representation for tree-based classifiers.
    """

    def __init__(self):
        self.url_aggregator = EmailURLAggregator()
        self.feature_names = STRUCTURED_FEATURE_NAMES

    def extract_text_statistics(self, record: EmailRecord) -> Dict[str, Any]:
        text = record.plain_text or ""
        char_count = len(text)
        words = text.split()
        word_count = len(words)

        upper_count = sum(1 for c in text if c.isupper())
        digit_count = sum(1 for c in text if c.isdigit())
        punct_count = sum(1 for c in text if c in string.punctuation)

        upper_ratio = upper_count / max(char_count, 1)
        digit_ratio = digit_count / max(char_count, 1)
        punct_ratio = punct_count / max(char_count, 1)

        exclamation_count = text.count("!")
        question_count = text.count("?")

        text_lower = text.lower()
        keyword_hits = sum(1 for kw in SUSPICIOUS_EMAIL_KEYWORDS if kw in text_lower)

        html_len = len(record.html or "")
        html_ratio = html_len / max(char_count + html_len, 1)

        return {
            "text_char_count": min(char_count, 50000),
            "text_word_count": min(word_count, 10000),
            "text_uppercase_ratio": round(upper_ratio, 4),
            "text_digit_ratio": round(digit_ratio, 4),
            "text_punct_ratio": round(punct_ratio, 4),
            "text_exclamation_count": min(exclamation_count, 50),
            "text_question_count": min(question_count, 50),
            "text_suspicious_keyword_count": min(keyword_hits, 30),
            "text_html_to_text_ratio": round(html_ratio, 4)
        }

    def extract_all_features(self, record: EmailRecord) -> Dict[str, Any]:
        """
        Extracts all structured feature dictionaries and combines them.
        """
        header_feats = extract_header_features(record)
        text_feats = self.extract_text_statistics(record)
        html_feats = extract_html_features(record)
        attach_feats = extract_attachment_features(record)
        url_feats = self.url_aggregator.analyze_urls(record)

        combined = {}
        combined.update(header_feats)
        combined.update(text_feats)
        combined.update(html_feats)
        combined.update(attach_feats)
        combined.update(url_feats)

        return combined

    def features_to_vector(self, feat_dict: Dict[str, Any]) -> np.ndarray:
        """
        Converts feature dictionary to a strict 1D numpy vector aligned with STRUCTURED_FEATURE_NAMES.
        """
        vec = []
        for name in self.feature_names:
            val = feat_dict.get(name, 0.0)
            if isinstance(val, (int, float, bool)):
                vec.append(float(val))
            else:
                vec.append(0.0)
        return np.array(vec, dtype=np.float32)

    def extract_vector(self, record: EmailRecord) -> Tuple[np.ndarray, Dict[str, Any]]:
        feat_dict = self.extract_all_features(record)
        vec = self.features_to_vector(feat_dict)
        return vec, feat_dict
