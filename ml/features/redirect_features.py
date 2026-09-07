from typing import Dict, Any, List
from urllib.parse import urlparse
from ml.features.url_features import extract_base_domain


def extract_redirect_features(initial_url: str, final_url: str, redirect_chain: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Extracts security features from HTTP redirect trajectories.
    """
    redirect_count = len(redirect_chain)
    has_redirect = 1 if redirect_count > 0 else 0

    init_parsed = urlparse(initial_url or "")
    final_parsed = urlparse(final_url or initial_url or "")

    init_host = init_parsed.hostname or ""
    final_host = final_parsed.hostname or ""

    init_base = extract_base_domain(init_host)
    final_base = extract_base_domain(final_host)

    has_domain_change = 1 if init_base and final_base and init_base != final_base else 0
    has_https_downgrade = 1 if init_parsed.scheme.lower() == "https" and final_parsed.scheme.lower() == "http" else 0

    # Domain hopping across chain
    unique_domains = set()
    if init_base:
        unique_domains.add(init_base)
    for hop in redirect_chain:
        hop_url = hop.get("url", "")
        h_host = urlparse(hop_url).hostname or ""
        h_base = extract_base_domain(h_host)
        if h_base:
            unique_domains.add(h_base)
    if final_base:
        unique_domains.add(final_base)

    suspicious_redirect = 1 if redirect_count >= 3 or len(unique_domains) >= 3 or has_https_downgrade else 0

    return {
        "redirect_count": redirect_count,
        "has_redirect": has_redirect,
        "has_domain_change": has_domain_change,
        "has_https_downgrade": has_https_downgrade,
        "num_unique_redirect_domains": len(unique_domains),
        "suspicious_redirect_pattern": suspicious_redirect,
        "redirect_chain": redirect_chain
    }
