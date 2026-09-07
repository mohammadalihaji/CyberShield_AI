import json
from typing import List, Dict, Any
import numpy as np

# Canonical CompPhish V4 URL Feature Schema (47 features)
URL_FEATURE_NAMES: List[str] = [
    "brand_subdomain",
    "brand_substring_domain",
    "brand_typo_dom",
    "fake_tld",
    "brand_in_path_query",
    "dots_path",
    "url_more_than_mean",
    "domain_more_than_mean",
    "gibberish",
    "domain_length",
    "url_length",
    "url_contains_ip",
    "presence_of_url_shortner",
    "special_characters_count",
    "no_of_at",
    "no_of_comma",
    "no_of_dollar",
    "no_of_semicolon",
    "no_of_space",
    "no_of_ampersand",
    "no_of_dots",
    "no_of_equal",
    "no_of_percent",
    "no_of_underscore",
    "no_of_hyphen",
    "no_of_questionmark",
    "no_of_colon",
    "no_of_slashes_inpath",
    "has_asterisk",
    "has_or",
    "has_embedded_url",
    "uses_https",
    "num_query_params",
    "numeric_proportion",
    "url_entropy",
    "hostname_digit_ratio",
    "has_redirections",
    "has_punycode",
    "count_www",
    "count_com",
    "url_has_high_risk_extension",
    "has_explicit_port",
    "total_words_url",
    "average_length_of_words",
    "longest_word_length",
    "shortest_word_length",
    "presence_of_free_hosting"
]

# Canonical CompPhish V4 Page / DOM / HTML Feature Schema (23 features)
PAGE_FEATURE_NAMES: List[str] = [
    "no_of_forms",
    "no_of_Images",
    "no_of_hyperlinks",
    "no_of_external_links",
    "no_of_internal_links",
    "no_of_null_links",
    "no_of_selfreference_links",
    "no_of_empty_links",
    "EmptyToExternalLinksRatio",
    "Risky_extensions_In_Html",
    "presence_of_shorten_url_html",
    "hidden_elements_html",
    "Script_loaded_from_ext_domain",
    "suspicious_inline_js",
    "is_footer_mismatch",
    "is_header_mismatch",
    "is_copyright_mismatch",
    "is_socials_mismatch",
    "is_favicon_mismatch",
    "has_missing_title",
    "title_mismatch_with_domain",
    "has_inline_event_handlers",
    "form_action_external"
]

# Combined 70-feature schema
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
        "dataset_name": "CompPhish Version 4",
        "url_feature_count": len(URL_FEATURE_NAMES),
        "page_feature_count": len(PAGE_FEATURE_NAMES),
        "combined_feature_count": len(COMBINED_FEATURE_NAMES),
        "url_features": URL_FEATURE_NAMES,
        "page_features": PAGE_FEATURE_NAMES,
        "combined_features": COMBINED_FEATURE_NAMES
    }
