import logging
from typing import Dict, Any, Optional
from urllib.parse import urlparse
import numpy as np

from ml.config import MODEL_DIR, MODEL_VERSION
from ml.features.url_features import extract_url_features, extract_base_domain
from ml.features.html_features import extract_html_features
from ml.features.redirect_features import extract_redirect_features
from ml.features.feature_schema import URL_FEATURE_NAMES, PAGE_FEATURE_NAMES, COMBINED_FEATURE_NAMES, dict_to_vector
from ml.inference.safe_fetcher import SafeWebpageFetcher, FetchResult
from ml.models.model_registry import ModelRegistry
from ml.models.calibration import ProbabilityCalibrator
from ml.explainability.explanation_engine import ExplanationEngine

logger = logging.getLogger(__name__)


class WebsiteSecurityAnalyzer:
    """
    High-level orchestrator for ML-based website security auditing.
    Executes URL feature extraction, SSRF-safe page fetching, static HTML/DOM analysis,
    model inference, probability calibration, and explainability generation.
    """

    def __init__(self, model_dir=MODEL_DIR):
        self.registry = ModelRegistry(model_dir)
        self.fetcher = SafeWebpageFetcher()

    def analyze(self, target_url: str) -> Dict[str, Any]:
        """
        Runs the end-to-end ML Website Security Audit.
        """
        if not target_url or not target_url.strip():
            return {
                "success": False,
                "error": "URL parameter is missing or empty.",
                "status": "INVALID_INPUT"
            }

        url = target_url.strip()
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        # 1. URL Feature Extraction
        url_features = extract_url_features(url)
        base_domain = url_features.get("base_domain", "")

        # 2. SSRF-Safe Webpage Fetch
        fetch_result = self.fetcher.fetch(url)
        page_available = fetch_result.success

        # 3. HTML, Script, Form, Redirect, Download Feature Extraction
        if page_available:
            page_features = extract_html_features(fetch_result.html_content, fetch_result.final_url)
            redirect_features = extract_redirect_features(
                initial_url=url,
                final_url=fetch_result.final_url,
                redirect_chain=fetch_result.redirect_chain
            )
        else:
            page_features = {}
            redirect_features = extract_redirect_features(
                initial_url=url,
                final_url=url,
                redirect_chain=fetch_result.redirect_chain
            )

        # 4. Check Model Readiness (No fake predictions)
        if not self.registry.is_model_ready():
            logger.info("Website security ML model is not trained yet. Returning development state.")
            
            pre_xai = ExplanationEngine.generate_explanation(
                url=url,
                risk_level="Awaiting Model Training",
                trusted_prob=0.0,
                phishing_prob=0.0,
                url_features=url_features,
                page_features=page_features,
                redirect_features=redirect_features,
                page_available=page_available,
                model_version=f"{MODEL_VERSION} (Awaiting CompPhish V4 Dataset Training)"
            )

            return {
                "success": False,
                "error": "Website security ML model is not trained yet. CompPhish V4 dataset training is required.",
                "status": "MODEL_NOT_READY",
                "url": url,
                "domain": base_domain,
                "page_analysis_available": page_available,
                "fetch_error": fetch_result.error if not page_available else None,
                "model_version": f"{MODEL_VERSION} (Awaiting Training)",
                "evidence": pre_xai["evidence"],
                "explanation_markdown": pre_xai["explanation_markdown"]
            }

        # 5. Model Inference with Trained Models
        models = self.registry.load_models()
        url_model = models.get("url_model")
        page_model = models.get("page_model")
        ensemble_model = models.get("ensemble_model")

        # URL Model probability
        url_vec = dict_to_vector(url_features, URL_FEATURE_NAMES).reshape(1, -1)
        if url_model:
            raw_url_probas = getattr(url_model, "model", url_model).predict_proba(url_vec)[0]
            url_prob = float(raw_url_probas[1]) if len(raw_url_probas) >= 2 else float(raw_url_probas[0])
        else:
            url_prob = 0.5

        # Page Model probability
        page_prob = None
        if page_available and page_model:
            page_vec = dict_to_vector(page_features, PAGE_FEATURE_NAMES).reshape(1, -1)
            raw_page_probas = getattr(page_model, "model", page_model).predict_proba(page_vec)[0]
            page_prob = float(raw_page_probas[1]) if len(raw_page_probas) >= 2 else float(raw_page_probas[0])

        # Combined 70-feature ensemble evaluation
        if ensemble_model and page_available:
            combined_dict = {}
            combined_dict.update(url_features)
            combined_dict.update(page_features)
            combined_vec = dict_to_vector(combined_dict, COMBINED_FEATURE_NAMES).reshape(1, -1)
            
            try:
                ens_probas = getattr(ensemble_model, "model", ensemble_model).predict_proba(combined_vec)[0]
                final_phish_prob = float(ens_probas[1]) if len(ens_probas) >= 2 else float(ens_probas[0])
            except Exception:
                final_phish_prob = (0.45 * url_prob + 0.55 * page_prob) if page_prob is not None else url_prob
        else:
            final_phish_prob = url_prob

        # Critical security signal adjustment:
        # Example: Sensitive credential input submitting to external domain
        if page_available:
            has_pwd = page_features.get("has_password_field", 0) > 0
            has_otp = page_features.get("has_otp_field", 0) > 0
            has_payment = page_features.get("has_payment_field", 0) > 0
            has_ext_form = page_features.get("form_action_external", 0) > 0 or page_features.get("has_external_form_submit", 0) > 0

            if (has_pwd or has_otp or has_payment) and has_ext_form:
                final_phish_prob = max(final_phish_prob, 0.92)

        cal_result = ProbabilityCalibrator.format_probabilities(final_phish_prob)

        # 6. Explainable AI and Evidence Generation
        xai_data = ExplanationEngine.generate_explanation(
            url=url,
            risk_level=cal_result["risk_level"],
            trusted_prob=cal_result["trusted_probability"],
            phishing_prob=cal_result["phishing_probability"],
            url_features=url_features,
            page_features=page_features,
            redirect_features=redirect_features,
            page_available=page_available,
            model_version=MODEL_VERSION
        )

        # 7. Assemble standardized API Response
        return {
            "success": True,
            "url": url,
            "final_url": fetch_result.final_url if page_available else url,
            "domain": base_domain,
            "risk_level": cal_result["risk_level"],
            "trusted_probability": cal_result["trusted_probability"],
            "phishing_probability": cal_result["phishing_probability"],
            "phishing_score": int(round(cal_result["phishing_score"])),
            "page_analysis_available": page_available,
            "url_analysis": {
                "risk": ProbabilityCalibrator.map_risk_level(url_prob),
                "score": round(url_prob * 100.0, 1)
            },
            "page_analysis": {
                "risk": ProbabilityCalibrator.map_risk_level(page_prob) if page_prob is not None else "UNAVAILABLE",
                "score": round(page_prob * 100.0, 1) if page_prob is not None else None
            },
            "form_analysis": {
                "total_forms": page_features.get("no_of_forms", page_features.get("total_forms", 0)),
                "has_password_field": bool(page_features.get("has_password_field", 0)),
                "has_otp_field": bool(page_features.get("has_otp_field", 0)),
                "has_payment_field": bool(page_features.get("has_payment_field", 0)),
                "has_external_form_submit": bool(page_features.get("form_action_external", page_features.get("has_external_form_submit", 0))),
                "form_domain_mismatch_count": page_features.get("form_domain_mismatch_count", 0)
            },
            "script_analysis": {
                "num_scripts": page_features.get("num_scripts", 0),
                "has_eval": bool(page_features.get("has_eval", 0)),
                "has_document_write": bool(page_features.get("has_document_write", 0)),
                "has_event_tampering": bool(page_features.get("has_inline_event_handlers", page_features.get("has_event_tampering", 0))),
                "has_base64_payload": bool(page_features.get("has_base64_payload", 0))
            },
            "redirect_analysis": {
                "redirect_count": redirect_features.get("redirect_count", 0),
                "has_domain_change": bool(redirect_features.get("has_domain_change", 0)),
                "has_https_downgrade": bool(redirect_features.get("has_https_downgrade", 0))
            },
            "download_analysis": {
                "num_download_links": page_features.get("num_download_links", 0),
                "has_executable_download": bool(page_features.get("Risky_extensions_In_Html", page_features.get("has_executable_download", 0)))
            },
            "security_indicators": {
                "password_field": bool(page_features.get("has_password_field", 0)),
                "otp_field": bool(page_features.get("has_otp_field", 0)),
                "payment_field": bool(page_features.get("has_payment_field", 0)),
                "external_form_submit": bool(page_features.get("form_action_external", page_features.get("has_external_form_submit", 0))),
                "suspicious_redirect": bool(redirect_features.get("suspicious_redirect_pattern", 0))
            },
            "evidence": xai_data["evidence"],
            "explanation_markdown": xai_data["explanation_markdown"],
            "model_version": xai_data["model_version"],
            "analysis_method": "ML + static webpage analysis",
            "ssl_valid": fetch_result.is_tls if page_available else (url.lower().startswith("https://")),
            "malware_found": bool(page_features.get("Risky_extensions_In_Html", page_features.get("has_executable_download", 0))),
            "domain_age": None,
            "reputation": None
        }
