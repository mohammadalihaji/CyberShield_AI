import os
import sys
import logging
from pathlib import Path
from typing import Dict, Any, Union, Optional
import numpy as np
import joblib

from ml.email.config import (
    MODEL_DIR,
    TEXT_MODEL_FILE,
    STRUCTURED_MODEL_FILE,
    META_MODEL_FILE,
    CALIBRATOR_FILE,
    MODEL_VERSION,
    DECISION_THRESHOLDS,
    TRANSFORMER_MODEL_NAME
)
from ml.email.schema import EmailRecord
from ml.email.parser import parse_raw_eml, parse_pasted_email
from ml.email.feature_extractor import EmailFeatureExtractor, STRUCTURED_FEATURE_NAMES
from ml.email.xai_engine import EmailXAIEngine

logger = logging.getLogger(__name__)


def assemble_meta_vector(p_text: float, p_struct: float, p_url: float) -> np.ndarray:
    p_text = np.clip(p_text, 1e-6, 1.0 - 1e-6)
    p_struct = np.clip(p_struct, 1e-6, 1.0 - 1e-6)
    p_url = np.clip(p_url, 1e-6, 1.0 - 1e-6)

    max_signal = max(p_text, p_struct)
    mean_signal = (p_text + p_struct + p_url) / 3.0
    text_struct_interaction = p_text * p_struct
    discrepancy = abs(p_text - p_struct)

    return np.array([[p_text, p_struct, p_url, max_signal, mean_signal, text_struct_interaction, discrepancy]], dtype=np.float32)


class EmailSecurityAnalyzer:
    """
    Main Production Email Security Engine.
    Executes multi-modal feature extraction, transformer text embedding,
    structured heuristics classification, stacking ensemble aggregation,
    probability calibration, and deterministic XAI reporting.
    """

    _instance = None

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super(EmailSecurityAnalyzer, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self.feature_extractor = EmailFeatureExtractor()
        self.xai_engine = EmailXAIEngine()
        self.text_embedder = None
        self.text_model_bundle = None
        self.struct_model_bundle = None
        self.meta_model = None
        self.calibrator = None
        self._load_models()
        self._initialized = True

    def _load_models(self):
        try:
            if (MODEL_DIR / TEXT_MODEL_FILE).exists():
                self.text_model_bundle = joblib.load(MODEL_DIR / TEXT_MODEL_FILE)
            if (MODEL_DIR / STRUCTURED_MODEL_FILE).exists():
                self.struct_model_bundle = joblib.load(MODEL_DIR / STRUCTURED_MODEL_FILE)
            if (MODEL_DIR / META_MODEL_FILE).exists():
                self.meta_model = joblib.load(MODEL_DIR / META_MODEL_FILE)
            if (MODEL_DIR / CALIBRATOR_FILE).exists():
                self.calibrator = joblib.load(MODEL_DIR / CALIBRATOR_FILE)
        except Exception as e:
            logger.warning(f"Error loading email models from {MODEL_DIR}: {e}")

    def _get_text_embedding(self, subject: str, body: str) -> np.ndarray:
        if self.text_embedder is None:
            try:
                from sentence_transformers import SentenceTransformer
                self.text_embedder = SentenceTransformer(TRANSFORMER_MODEL_NAME)
            except Exception as e:
                logger.warning(f"Could not load SentenceTransformer: {e}")
                return np.zeros((1, 384), dtype=np.float32)

        clean_body = " ".join(body.split()[:400])
        combined = f"[SUBJECT] {subject} [BODY] {clean_body}"
        return self.text_embedder.encode([combined])

    def analyze_record(self, record: EmailRecord) -> Dict[str, Any]:
        """
        Analyzes an EmailRecord through the complete multi-modal ML pipeline:
        1. Multi-modal feature extraction (headers, DOM, attachments, contextual URLs)
        2. Transformer text embeddings & structured tree model prediction
        3. Contextual URL security evaluation
        4. Out-of-fold stacking ensemble & probability calibration
        5. Deterministic multi-factor evidence aggregation
        6. Explainable AI reporting
        """
        # 1. Structured Feature Extraction
        struct_vec, struct_dict = self.feature_extractor.extract_vector(record)
        url_metrics = struct_dict.get("url_metrics", {})
        classified_urls = struct_dict.get("classified_urls", [])
        url_risk = float(struct_dict.get("email_max_url_risk", 0.0))

        # 2. Text Model Prediction
        text_prob = 0.5
        if self.text_model_bundle is not None and "binary_classifier" in self.text_model_bundle:
            emb = self._get_text_embedding(record.subject, record.plain_text)
            text_prob = float(self.text_model_bundle["binary_classifier"].predict_proba(emb)[0, 1])

        # 3. Structured Model Prediction
        struct_prob = 0.5
        if self.struct_model_bundle is not None and "binary_model" in self.struct_model_bundle:
            struct_prob = float(self.struct_model_bundle["binary_model"].predict_proba(struct_vec.reshape(1, -1))[0, 1])

        # 4. Out-of-Fold Stacking & Initial Calibrated Probability
        meta_vec = assemble_meta_vector(text_prob, struct_prob, url_risk)
        
        if self.calibrator is not None:
            raw_cal_prob = float(self.calibrator.predict_proba(meta_vec)[0, 1])
        elif self.meta_model is not None:
            raw_cal_prob = float(self.meta_model.predict_proba(meta_vec)[0, 1])
        else:
            raw_cal_prob = float(0.40 * text_prob + 0.35 * struct_prob + 0.25 * url_risk)

        # 5. Deterministic Multi-Factor Evidence-Based Aggregation
        # Identifies confirmed threats vs suspicious signals vs verified authentication
        has_executable_attachment = bool(
            struct_dict.get("has_executable_attachment", 0) or
            struct_dict.get("has_double_extension_attachment", 0) or
            struct_dict.get("has_macro_attachment", 0)
        )
        has_anchor_mismatch = bool(struct_dict.get("html_anchor_href_mismatch_count", 0) > 0)
        has_brand_impersonation = bool(struct_dict.get("email_has_brand_in_subdomain_url", 0))
        has_hidden_form = bool(struct_dict.get("has_hidden_form", 0))
        
        malicious_url_count = url_metrics.get("malicious_urls", 0)
        suspicious_url_count = url_metrics.get("suspicious_urls", 0)

        spf_ok = (record.spf_verdict == "pass")
        dkim_ok = (record.dkim_verdict == "pass")
        auth_passed = spf_ok and dkim_ok
        auth_failed = (record.spf_verdict == "fail" or record.dkim_verdict == "fail" or record.dmarc_verdict == "fail")
        from_reply_mismatch = bool(struct_dict.get("from_reply_to_mismatch", 0))

        has_hard_threat = (
            has_executable_attachment or
            has_anchor_mismatch or
            has_brand_impersonation or
            has_hidden_form or
            (malicious_url_count > 0) or
            (auth_failed and from_reply_mismatch)
        )

        cal_prob = raw_cal_prob

        # Case A: Confirmed Hard Threat -> MALICIOUS
        if has_hard_threat:
            cal_prob = max(cal_prob, 0.85)
            verdict = "Malicious"
            classification = "phishing"

        # Case B: Suspicious Signals without Hard Threats -> SUSPICIOUS
        elif suspicious_url_count > 0:
            # Dynamic IP / unknown dynamic hostname without hard payload -> strictly SUSPICIOUS
            cal_prob = min(max(cal_prob, 0.45), 0.60)
            verdict = "Suspicious"
            classification = "suspicious"

        # Case C: Authenticated Sender + Zero Malicious/Suspicious Links/Attachments -> SAFE
        elif auth_passed and not has_hard_threat and suspicious_url_count == 0:
            # Cryptographically authenticated, clean attachments, clean links
            # Dampen text-only false positives on normal job/placement/newsletter words
            if cal_prob >= DECISION_THRESHOLDS["LEGITIMATE_MAX"]:
                cal_prob = min(cal_prob * 0.35, 0.25)
            verdict = "Safe"
            classification = "legitimate"

        # Case D: General Classification
        else:
            is_empty = (not record.plain_text and not record.html and not record.subject)
            if is_empty or abs(cal_prob - 0.50) < 0.05:
                verdict = "Suspicious"
                classification = "uncertain" if is_empty else "suspicious"
            elif cal_prob < DECISION_THRESHOLDS["LEGITIMATE_MAX"]:
                verdict = "Safe"
                classification = "legitimate"
            elif cal_prob < DECISION_THRESHOLDS["SUSPICIOUS_MAX"]:
                verdict = "Suspicious"
                classification = "suspicious"
            else:
                verdict = "Malicious"
                classification = "phishing" if (url_risk >= 0.70 or from_reply_mismatch) else "spam"

        risk_score = round(cal_prob * 100.0, 1)
        ham_prob = round(1.0 - cal_prob, 4)
        phish_prob = round(cal_prob if classification == "phishing" else cal_prob * 0.7, 4)
        spam_prob = round(cal_prob if classification == "spam" else cal_prob * 0.3, 4)

        pred_summary = {
            "verdict": verdict,
            "classification": classification,
            "risk_score": risk_score,
            "calibrated_probability": round(cal_prob, 4),
            "text_probability": round(text_prob, 4),
            "structured_probability": round(struct_prob, 4),
            "url_probability": round(url_risk, 4),
            "ensemble_probability": round(cal_prob, 4),
            "legitimate_probability": ham_prob,
            "spam_probability": spam_prob,
            "phishing_probability": phish_prob,
            "url_metrics": url_metrics,
            "classified_urls": classified_urls,
            "model_version": MODEL_VERSION,
            "analysis_status": "complete"
        }

        # 6. Generate Explainable Evidence & Markdown
        evidence = self.xai_engine.generate_evidence(record, struct_dict, pred_summary)
        markdown_report = self.xai_engine.generate_markdown_report(record, pred_summary, evidence)

        return {
            "success": True,
            "verdict": verdict,
            "classification": classification,
            "risk_score": risk_score,
            "calibrated_probability": round(cal_prob, 4),
            "text_probability": round(text_prob, 4),
            "structured_probability": round(struct_prob, 4),
            "url_probability": round(url_risk, 4),
            "ensemble_probability": round(cal_prob, 4),
            "legitimate_probability": ham_prob,
            "spam_probability": spam_prob,
            "phishing_probability": phish_prob,
            "evidence": evidence,
            "explanation_markdown": markdown_report,
            "url_metrics": url_metrics,
            "classified_urls": classified_urls,
            "model_signals": {
                "text_model": round(text_prob * 100, 1),
                "structured_model": round(struct_prob * 100, 1),
                "url_security": round(url_risk * 100, 1),
                "ensemble": round(cal_prob * 100, 1)
            },
            "meta": {
                "sender": record.from_address,
                "sender_domain": record.from_domain,
                "subject": record.subject,
                "url_count": url_metrics.get("unique_clickable_hrefs", len(record.clickable_hrefs or record.urls)),
                "attachment_count": len(record.attachments),
                "spf": record.spf_verdict,
                "dkim": record.dkim_verdict,
                "dmarc": record.dmarc_verdict
            },
            "model_version": MODEL_VERSION
        }

    def analyze_eml_bytes(self, eml_bytes: bytes) -> Dict[str, Any]:
        record = parse_raw_eml(eml_bytes, source_dataset="live_eml_upload")
        return self.analyze_record(record)

    def analyze_pasted(self, sender: str, body_or_headers: str, subject: str = "") -> Dict[str, Any]:
        record = parse_pasted_email(sender=sender, body_or_headers=body_or_headers, subject=subject)
        return self.analyze_record(record)
