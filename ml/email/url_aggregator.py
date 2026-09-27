from typing import Dict, Any, List, Optional, Set
import logging
import numpy as np
from urllib.parse import urlparse

from ml.email.schema import EmailRecord
from ml.features.url_features import extract_url_features
from ml.models.model_registry import ModelRegistry
from ml.email.domain_analyzer import get_organizational_domain
from ml.email.url_classifier import (
    normalize_url,
    classify_single_url,
    detect_brand_impersonation,
    compute_contextual_url_risk,
    URLCategory,
    PHISHING_PATH_KEYWORDS,
)

logger = logging.getLogger(__name__)


class EmailURLAggregator:
    """
    Extracts lexical, structural, functional, and ML risk scores for all URLs in an email,
    directly reusing CyberShield's pre-trained CompPhish V4 URL security model.

    Two risk scores are maintained per URL:
    - raw_model_risk  : the raw CompPhish V4 probability — used unchanged for ensemble meta-vector
    - contextual_risk : email-context-aware override — used for user-facing Link Analysis counts
    """

    def __init__(self):
        registry = ModelRegistry()
        models = registry.load_models()
        self.url_model = models.get("url_model") if models.get("is_ready") else None

    def _predict_risk(self, features: Dict[str, Any]) -> float:
        """Returns a CompPhish score for one concrete URL representation."""
        if self.url_model is not None and hasattr(self.url_model, "predict_single"):
            try:
                return float(self.url_model.predict_single(features))
            except Exception:
                pass
        return min(1.0, (
            (0.40 if features.get("url_contains_ip", 0) else 0.0) +
            (0.30 if features.get("presence_of_url_shortner", 0) else 0.0) +
            (0.35 if features.get("fake_tld", 0) or features.get("suspicious_tld_indicator", 0) else 0.0) +
            (0.15 if features.get("suspicious_keywords_count", 0) > 0 else 0.0)
        ))

    @staticmethod
    def _has_semantic_threat(url: str, features: Dict[str, Any], brand_check: Dict[str, Any]) -> bool:
        """Signals that justify elevating a tracking wrapper or destination."""
        path = (urlparse(url).path or "").lower()
        return bool(
            brand_check.get("is_impersonation", False)
            or features.get("url_contains_ip", 0)
            or features.get("has_punycode", 0)
            or features.get("fake_tld", 0)
            or features.get("suspicious_tld_indicator", 0)
            or any(keyword in path for keyword in PHISHING_PATH_KEYWORDS)
        )

    def _contextual_tracking_risk(
        self,
        wrapper: Dict[str, Any],
        wrapper_features: Dict[str, Any],
        wrapper_brand: Dict[str, Any],
        wrapper_risk: float,
        destination: Dict[str, Any],
        destination_features: Dict[str, Any],
        destination_brand: Dict[str, Any],
        destination_risk: float,
        sender_org: str,
    ) -> tuple[float, str]:
        """Combines wrapper and destination analysis for a tracking URL.

        Lexical entropy in an opaque wrapper is recorded but cannot alone make a
        link malicious. A risky wrapper or destination still wins when it has
        semantic evidence (IP, IDN, abused TLD, impersonation, phishing path).
        """
        wrapper_direct = dict(wrapper)
        wrapper_direct["category"] = URLCategory.DIRECT
        wrapper_context, wrapper_reason = compute_contextual_url_risk(
            wrapper_direct, wrapper_brand, wrapper_features, wrapper_risk, sender_org
        )
        destination_context, destination_reason = compute_contextual_url_risk(
            destination, destination_brand, destination_features, destination_risk, sender_org
        )

        wrapper_has_threat = self._has_semantic_threat(
            wrapper.get("url", ""), wrapper_features, wrapper_brand
        )
        destination_has_threat = self._has_semantic_threat(
            destination.get("url", ""), destination_features, destination_brand
        )

        if destination_has_threat:
            return destination_context, f"Destination evidence: {destination_reason}"
        if wrapper_has_threat:
            return wrapper_context, f"Wrapper evidence: {wrapper_reason}"

        return 0.05, (
            "Tracking/redirect wrapper and decoded destination have no semantic "
            "threat indicators; wrapper lexical score retained for audit only"
        )

    def analyze_urls(self, record: EmailRecord) -> Dict[str, Any]:
        raw_urls = record.urls or []
        raw_occurrences = record.url_occurrences or raw_urls
        total_url_occurrences = len(raw_occurrences)
        unique_raw_url_count = len(set(raw_occurrences))
        unique_clickable_href_count = len({
            normalize_url(url) for url in (record.clickable_href_occurrences or []) if normalize_url(url)
        })

        if total_url_occurrences == 0:
            return {
                "email_url_count": 0,
                "email_unique_domain_count": 0,
                "email_suspicious_url_count": 0,
                "email_max_url_risk": 0.0,
                "email_avg_url_risk": 0.0,
                "email_has_ip_url": 0,
                "email_has_shortened_url": 0,
                "email_has_punycode_url": 0,
                "email_has_suspicious_tld_url": 0,
                "email_has_brand_in_subdomain_url": 0,
                "email_external_domain_url_ratio": 0.0,
                "url_risk_scores": [],
                "url_metrics": {
                    "total_url_occurrences": 0,
                    "unique_raw_urls": 0,
                    "unique_normalized_urls": 0,
                    "unique_clickable_hrefs": 0,
                    "unique_urls": 0,
                    "unique_destinations": 0,
                    "unique_domains": 0,
                    "tracking_urls": 0,
                    "redirect_urls": 0,
                    "unsubscribe_urls": 0,
                    "social_urls": 0,
                    "sender_domain_urls": 0,
                    "image_cdn_urls": 0,
                    "suspicious_urls": 0,
                    "malicious_urls": 0,
                    "max_raw_url_model_score": 0.0,
                    "contextual_threat_verdict": "Clean — No Malicious Links Detected"
                },
                "classified_urls": []
            }

        sender_domain = record.from_domain.lower()
        sender_org = get_organizational_domain(sender_domain)

        # Normalize and deduplicate URLs
        normalized_urls: List[str] = []
        original_urls_by_normalized: Dict[str, List[str]] = {}
        seen_urls: Set[str] = set()
        for u in raw_occurrences:
            norm = normalize_url(u)
            if not norm:
                continue
            original_urls_by_normalized.setdefault(norm, []).append(u)
            if norm not in seen_urls:
                seen_urls.add(norm)
                normalized_urls.append(norm)

        unique_url_count = len(normalized_urls)
        unique_domains: Set[str] = set()
        unique_destinations: Set[str] = set()
        external_domains_count = 0

        tracking_count = 0
        redirect_count = 0
        unsubscribe_count = 0
        social_count = 0
        sender_domain_count = 0
        image_cdn_count = 0

        # User-facing counts (driven by contextual_risk)
        suspicious_url_count = 0
        malicious_url_count = 0

        has_ip = 0
        has_shortened = 0
        has_punycode = 0
        has_suspicious_tld = 0
        has_brand_impersonation = 0

        # raw_model_risks feeds the ensemble — NEVER altered by context logic
        raw_model_risks: List[float] = []
        classified_urls: List[Dict[str, Any]] = []

        for u in normalized_urls:
            # Score the original clickable wrapper and, when present, its decoded
            # destination independently.  This preserves CompPhish telemetry
            # without mistaking a long opaque wrapper for a malicious target.
            classification_info = classify_single_url(u, sender_domain=sender_domain)
            dest_url = classification_info.get("destination_url", u)
            dest_domain = classification_info.get("destination_domain", "")
            org_dom = classification_info.get("org_domain", "")
            cat = classification_info.get("category", URLCategory.DIRECT)
            destination_info = classify_single_url(dest_url, sender_domain=sender_domain)

            if org_dom:
                unique_domains.add(org_dom)
            if dest_domain:
                unique_domains.add(dest_domain)
                unique_destinations.add(dest_url)
                if sender_org and dest_domain != sender_org:
                    external_domains_count += 1

            if cat == URLCategory.TRACKING:
                tracking_count += 1
            elif cat == URLCategory.REDIRECT:
                redirect_count += 1
            elif cat == URLCategory.UNSUBSCRIBE:
                unsubscribe_count += 1
            elif cat == URLCategory.SOCIAL:
                social_count += 1
            elif cat == URLCategory.SENDER_DOMAIN:
                sender_domain_count += 1
            elif cat == URLCategory.IMAGE_CDN:
                image_cdn_count += 1

            wrapper_brand = detect_brand_impersonation(u, sender_domain=sender_domain)
            destination_brand = detect_brand_impersonation(dest_url, sender_domain=sender_domain)
            wrapper_features = extract_url_features(u)
            destination_features = extract_url_features(dest_url)
            wrapper_risk = self._predict_risk(wrapper_features)
            destination_risk = self._predict_risk(destination_features)
            combined_raw_risk = max(wrapper_risk, destination_risk)

            for features, brand_check in (
                (wrapper_features, wrapper_brand),
                (destination_features, destination_brand),
            ):
                has_ip |= int(bool(features.get("url_contains_ip", 0)))
                has_shortened |= int(bool(features.get("presence_of_url_shortner", 0)))
                has_punycode |= int(bool(features.get("has_punycode", 0)))
                has_suspicious_tld |= int(bool(
                    features.get("fake_tld", 0) or features.get("suspicious_tld_indicator", 0)
                ))
                has_brand_impersonation |= int(bool(brand_check.get("is_impersonation", False)))

            # Keep the highest individual CompPhish probability per clickable
            # URL for the existing ensemble feature and transparent reporting.
            raw_model_risks.append(round(combined_raw_risk, 4))

            if cat in {URLCategory.TRACKING, URLCategory.REDIRECT}:
                contextual_risk, contextual_reason = self._contextual_tracking_risk(
                    classification_info, wrapper_features, wrapper_brand, wrapper_risk,
                    destination_info, destination_features, destination_brand,
                    destination_risk, sender_org,
                )
            else:
                contextual_risk, contextual_reason = compute_contextual_url_risk(
                    classification=classification_info,
                    brand_check=destination_brand,
                    url_features=destination_features,
                    raw_model_risk=destination_risk,
                    sender_org=sender_org,
                )

            # 6. User-facing link counts driven by contextual_risk
            if contextual_risk >= 0.70:
                malicious_url_count += 1
            elif contextual_risk >= 0.40:
                suspicious_url_count += 1

            # Enrich classification record
            classification_info["wrapper_risk"] = round(wrapper_risk, 4)
            classification_info["destination_risk"] = round(destination_risk, 4)
            classification_info["raw_url_model_risk"] = round(combined_raw_risk, 4)
            classification_info["contextual_risk"] = round(contextual_risk, 4)
            classification_info["contextual_reason"] = contextual_reason
            classification_info["wrapper_brand_check"] = wrapper_brand
            classification_info["brand_check"] = destination_brand
            classification_info["wrapper_features"] = wrapper_features
            classification_info["destination_features"] = destination_features
            classification_info["original_urls"] = original_urls_by_normalized.get(u, [u])
            classification_info["occurrence_count"] = len(classification_info["original_urls"])
            classification_info["is_social"] = cat == URLCategory.SOCIAL
            classification_info["is_unsubscribe"] = cat == URLCategory.UNSUBSCRIBE
            classification_info["is_cdn_asset"] = cat == URLCategory.IMAGE_CDN
            classification_info["final_classification"] = (
                "MALICIOUS" if contextual_risk >= 0.70 else
                ("SUSPICIOUS" if contextual_risk >= 0.40 else "SAFE")
            )
            classified_urls.append(classification_info)

            logger.debug(
                f"URL: {u} | category: {cat} | wrapper_risk: {wrapper_risk:.4f} | "
                f"destination_risk: {destination_risk:.4f} | "
                f"contextual_risk: {contextual_risk:.4f} | reason: {contextual_reason} | "
                f"brand_impersonation: {destination_brand.get('is_impersonation')} | "
                f"destination_domain: {dest_domain}"
            )

        # Ensemble meta-vector uses raw model scores exclusively
        max_raw_risk = max(raw_model_risks) if raw_model_risks else 0.0
        avg_raw_risk = sum(raw_model_risks) / max(len(raw_model_risks), 1) if raw_model_risks else 0.0
        ext_ratio = external_domains_count / max(unique_url_count, 1)

        # Contextual threat verdict for UI
        if malicious_url_count > 0:
            contextual_verdict = f"⚠ {malicious_url_count} Malicious Link(s) Detected"
        elif suspicious_url_count > 0:
            contextual_verdict = f"⚠ {suspicious_url_count} Suspicious Link(s)"
        else:
            contextual_verdict = "✓ Clean — No Malicious Links Detected"

        url_metrics = {
            "total_url_occurrences": total_url_occurrences,
            "unique_raw_urls": unique_raw_url_count,
            "unique_normalized_urls": unique_url_count,
            "unique_clickable_hrefs": unique_clickable_href_count,
            "unique_urls": unique_url_count,
            "unique_destinations": len(unique_destinations) if unique_destinations else unique_url_count,
            "unique_domains": len(unique_domains),
            "tracking_urls": tracking_count,
            "redirect_urls": redirect_count,
            "unsubscribe_urls": unsubscribe_count,
            "social_urls": social_count,
            "sender_domain_urls": sender_domain_count,
            "image_cdn_urls": image_cdn_count,
            "suspicious_urls": suspicious_url_count,
            "malicious_urls": malicious_url_count,
            "max_raw_url_model_score": round(max_raw_risk, 4),
            "contextual_threat_verdict": contextual_verdict
        }

        return {
            # Ensemble meta-vector features (raw scores, unchanged)
            "email_url_count": min(unique_url_count, 50),
            "email_unique_domain_count": min(len(unique_domains), 20),
            "email_suspicious_url_count": min(suspicious_url_count, 20),
            "email_max_url_risk": round(max_raw_risk, 4),
            "email_avg_url_risk": round(avg_raw_risk, 4),
            "email_has_ip_url": has_ip,
            "email_has_shortened_url": has_shortened,
            "email_has_punycode_url": has_punycode,
            "email_has_suspicious_tld_url": has_suspicious_tld,
            "email_has_brand_in_subdomain_url": has_brand_impersonation,
            "email_external_domain_url_ratio": round(ext_ratio, 4),
            # Debug and UI
            "url_risk_scores": raw_model_risks,
            "url_metrics": url_metrics,
            "classified_urls": classified_urls
        }
