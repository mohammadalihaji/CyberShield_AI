import json
from typing import List, Dict, Any
import numpy as np

# Canonical URL Feature Schema
URL_FEATURE_NAMES: List[str] = [
    "url_length",
    "hostname_length",
    "path_length",
    "query_length",
    "fragment_length",
    "num_dots",
    "num_hyphens",
    "num_underscores",
    "num_slashes",
    "num_percent",
    "num_at",
    "num_double_slash_path",
    "num_question_marks",
    "num_equal_signs",
    "num_ampersands",
    "num_digits",
    "num_special_chars",
    "digit_ratio",
    "special_char_ratio",
    "subdomain_count",
    "subdomain_length",
    "url_entropy",
    "hostname_entropy",
    "path_entropy",
    "query_entropy",
    "is_ip_address",
    "has_port_in_url",
    "is_suspicious_port",
    "is_punycode",
    "is_https",
    "has_at_symbol",
    "excessive_percent_encoding",
    "is_shortened_url",
    "suspicious_tld_indicator",
    "suspicious_keywords_count",
    "brand_keywords_count",
    "brand_in_subdomain_or_path"
]

# Canonical HTML / DOM / Page Feature Schema
PAGE_FEATURE_NAMES: List[str] = [
    "html_size",
    "has_title",
    "title_length",
    "title_domain_similarity",
    "visible_text_length",
    "text_to_html_ratio",
    "num_links",
    "num_internal_links",
    "num_external_links",
    "external_link_ratio",
    "empty_link_ratio",
    "num_images",
    "num_external_images",
    "external_image_ratio",
    "num_meta_tags",
    "has_meta_refresh",
    "num_iframes",
    "num_external_iframes",
    "has_hidden_iframe",
    "total_forms",
    "has_password_field",
    "num_password_fields",
    "has_email_field",
    "num_email_fields",
    "has_username_field",
    "num_username_fields",
    "has_otp_field",
    "num_otp_fields",
    "has_payment_field",
    "num_payment_fields",
    "has_cvv_field",
    "num_cvv_fields",
    "has_pin_field",
    "num_pin_fields",
    "has_personal_info_field",
    "num_personal_info_fields",
    "num_hidden_inputs",
    "num_submit_buttons",
    "has_external_form_submit",
    "num_external_form_submits",
    "has_empty_form_action",
    "has_mailto_form_action",
    "has_insecure_form_action",
    "form_domain_mismatch_count",
    "num_scripts",
    "num_inline_scripts",
    "num_external_scripts",
    "num_external_script_domains",
    "external_script_ratio",
    "total_script_length",
    "max_script_length",
    "script_entropy",
    "has_eval",
    "has_function_constructor",
    "has_document_write",
    "has_unescape",
    "has_atob",
    "has_cookie_access",
    "has_storage_access",
    "has_window_location_redirect",
    "has_event_tampering",
    "has_base64_payload",
    "num_download_links",
    "num_executable_downloads",
    "has_executable_download",
    "num_archive_downloads",
    "has_auto_download_tag"
]

# Combined Ensemble Feature Schema
COMBINED_FEATURE_NAMES: List[str] = URL_FEATURE_NAMES + PAGE_FEATURE_NAMES


def dict_to_vector(features_dict: Dict[str, Any], schema: List[str]) -> np.ndarray:
    """
    Converts a feature dictionary to a 1D numpy array aligned with the provided schema.
    Missing values default to 0.0.
    """
    vec = []
    for name in schema:
        val = features_dict.get(name, 0.0)
        if isinstance(val, (bool, int, float)):
            vec.append(float(val))
        elif isinstance(val, str):
            try:
                vec.append(float(val))
            except ValueError:
                vec.append(0.0)
        else:
            vec.append(0.0)
    return np.array(vec, dtype=np.float32)


def get_schema_metadata() -> Dict[str, Any]:
    """Returns serializable metadata describing the feature schema."""
    return {
        "url_feature_count": len(URL_FEATURE_NAMES),
        "page_feature_count": len(PAGE_FEATURE_NAMES),
        "combined_feature_count": len(COMBINED_FEATURE_NAMES),
        "url_features": URL_FEATURE_NAMES,
        "page_features": PAGE_FEATURE_NAMES,
        "combined_features": COMBINED_FEATURE_NAMES
    }
