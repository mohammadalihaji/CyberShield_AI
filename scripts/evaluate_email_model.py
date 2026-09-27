import os
import sys
import json
import logging
from pathlib import Path
import pandas as pd
import numpy as np
import joblib

from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, average_precision_score, confusion_matrix, brier_score_loss
)

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ml.email.config import (
    PROCESSED_DATA_DIR,
    ARTIFACTS_DIR,
    MODEL_DIR,
    TEXT_MODEL_FILE,
    STRUCTURED_MODEL_FILE,
    META_MODEL_FILE,
    CALIBRATOR_FILE,
    FEATURE_SCHEMA_FILE,
    DECISION_THRESHOLDS
)
from ml.email.feature_extractor import STRUCTURED_FEATURE_NAMES

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("evaluate_model")


def calculate_ece(y_true: np.ndarray, y_prob: np.ndarray, n_bins: int = 10) -> float:
    bin_boundaries = np.linspace(0, 1, n_bins + 1)
    ece = 0.0
    for i in range(n_bins):
        bin_lower, bin_upper = bin_boundaries[i], bin_boundaries[i + 1]
        mask = (y_prob >= bin_lower) & (y_prob < bin_upper) if i < n_bins - 1 else (y_prob >= bin_lower) & (y_prob <= bin_upper)
        if np.sum(mask) > 0:
            bin_acc = np.mean(y_true[mask])
            bin_conf = np.mean(y_prob[mask])
            ece += np.sum(mask) * np.abs(bin_acc - bin_conf)
    return float(ece / max(len(y_true), 1))


def assemble_meta_features(p_text: np.ndarray, p_struct: np.ndarray, p_url: np.ndarray) -> np.ndarray:
    p_text = np.clip(p_text, 1e-6, 1.0 - 1e-6)
    p_struct = np.clip(p_struct, 1e-6, 1.0 - 1e-6)
    p_url = np.clip(p_url, 1e-6, 1.0 - 1e-6)

    max_signal = np.maximum(p_text, p_struct)
    mean_signal = (p_text + p_struct + p_url) / 3.0
    text_struct_interaction = p_text * p_struct
    discrepancy = np.abs(p_text - p_struct)

    return np.column_stack([
        p_text, p_struct, p_url, max_signal, mean_signal, text_struct_interaction, discrepancy
    ]).astype(np.float32)


def evaluate_all():
    logger.info("Loading models and evaluation datasets...")
    cache_dir = ARTIFACTS_DIR / "embedding_cache"
    struct_cache_dir = ARTIFACTS_DIR / "structured_cache"

    df_test_in = pd.read_parquet(PROCESSED_DATA_DIR / "test_in_dist.parquet")
    df_test_cross = pd.read_parquet(PROCESSED_DATA_DIR / "test_cross_dataset.parquet")

    label_map = {"ham": 0, "spam": 1, "phishing": 2}
    y_test_in_3 = df_test_in["label"].map(label_map).values
    y_test_cross_3 = df_test_cross["label"].map(label_map).values

    y_test_in_bin = (y_test_in_3 > 0).astype(int)
    y_test_cross_bin = (y_test_cross_3 > 0).astype(int)

    # Load artifacts
    text_bundle = joblib.load(MODEL_DIR / TEXT_MODEL_FILE)
    text_model = text_bundle["binary_classifier"]

    struct_bundle = joblib.load(MODEL_DIR / STRUCTURED_MODEL_FILE)
    struct_model = struct_bundle["binary_model"]

    calibrator = joblib.load(MODEL_DIR / CALIBRATOR_FILE)
    baseline_data = joblib.load(ARTIFACTS_DIR / "baseline_model.joblib")
    baseline_tfidf = baseline_data["tfidf"]
    baseline_clf = baseline_data["model_bin"]

    # In-Distribution Features
    X_test_in_emb = np.load(cache_dir / "test_in_embeddings.npy")
    X_test_in_struct = np.load(struct_cache_dir / "test_in_struct_features.npy")
    url_risk_idx = STRUCTURED_FEATURE_NAMES.index("email_max_url_risk")
    url_risk_test_in = X_test_in_struct[:, url_risk_idx]

    # Cross-Dataset Features
    X_test_cross_emb = np.load(cache_dir / "test_cross_embeddings.npy")
    X_test_cross_struct = np.load(struct_cache_dir / "test_cross_struct_features.npy")
    url_risk_test_cross = X_test_cross_struct[:, url_risk_idx]

    # Model Predictions
    p_text_in = text_model.predict_proba(X_test_in_emb)[:, 1]
    p_struct_in = struct_model.predict_proba(X_test_in_struct)[:, 1]
    X_meta_in = assemble_meta_features(p_text_in, p_struct_in, url_risk_test_in)
    p_cal_in = calibrator.predict_proba(X_meta_in)[:, 1]

    p_text_cross = text_model.predict_proba(X_test_cross_emb)[:, 1]
    p_struct_cross = struct_model.predict_proba(X_test_cross_struct)[:, 1]
    X_meta_cross = assemble_meta_features(p_text_cross, p_struct_cross, url_risk_test_cross)
    p_cal_cross = calibrator.predict_proba(X_meta_cross)[:, 1]

    def compute_metrics(y_true, y_prob, threshold=0.50):
        preds = (y_prob >= threshold).astype(int)
        acc = float(accuracy_score(y_true, preds))
        prec = float(precision_score(y_true, preds, zero_division=0))
        rec = float(recall_score(y_true, preds, zero_division=0))
        f1 = float(f1_score(y_true, preds, zero_division=0))
        roc = float(roc_auc_score(y_true, y_prob))
        pr_auc = float(average_precision_score(y_true, y_prob))
        brier = float(brier_score_loss(y_true, y_prob))
        ece = calculate_ece(y_true, y_prob)

        cm = confusion_matrix(y_true, preds)
        tn, fp, fn, tp = cm.ravel()
        fpr = float(fp / max(tn + fp, 1))
        fnr = float(fn / max(tp + fn, 1))

        return {
            "accuracy": round(acc, 4),
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1": round(f1, 4),
            "roc_auc": round(roc, 4),
            "pr_auc": round(pr_auc, 4),
            "brier_score": round(brier, 4),
            "expected_calibration_error": round(ece, 4),
            "false_positive_rate": round(fpr, 4),
            "false_negative_rate": round(fnr, 4),
            "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)}
        }

    # Baseline on in-dist and cross
    with open(ARTIFACTS_DIR / "baseline_metrics.json", "r", encoding="utf-8") as f:
        baseline_report = json.load(f)

    adv_in_metrics = compute_metrics(y_test_in_bin, p_cal_in)
    adv_cross_metrics = compute_metrics(y_test_cross_bin, p_cal_cross)

    # Sub-model breakdowns on In-Distribution
    text_in_metrics = compute_metrics(y_test_in_bin, p_text_in)
    struct_in_metrics = compute_metrics(y_test_in_bin, p_struct_in)

    # Granular Phishing-Specific Recall within Malicious
    phish_mask_in = (y_test_in_3 == 2)
    phish_recall_in = float(np.mean(p_cal_in[phish_mask_in] >= 0.50)) if np.sum(phish_mask_in) > 0 else 0.0

    phish_mask_cross = (y_test_cross_3 == 2)
    phish_recall_cross = float(np.mean(p_cal_cross[phish_mask_cross] >= 0.50)) if np.sum(phish_mask_cross) > 0 else 0.0

    full_evaluation = {
        "evaluation_timestamp": "2026-09-27T11:55:00Z",
        "in_distribution_test_samples": len(y_test_in_bin),
        "cross_dataset_test_samples": len(y_test_cross_bin),
        "phishing_specific_recall": {
            "in_distribution": round(phish_recall_in, 4),
            "cross_dataset": round(phish_recall_cross, 4)
        },
        "models_comparison": {
            "baseline_tfidf_lr": {
                "in_distribution": baseline_report["in_distribution_test_metrics"],
                "cross_dataset": baseline_report["cross_dataset_test_metrics"]
            },
            "text_model_minilm": {
                "in_distribution": text_in_metrics
            },
            "structured_model": {
                "in_distribution": struct_in_metrics
            },
            "advanced_hybrid_stacking": {
                "in_distribution": adv_in_metrics,
                "cross_dataset": adv_cross_metrics
            }
        }
    }

    report_path = ARTIFACTS_DIR / "evaluation_report.json"
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(full_evaluation, f, indent=2)

    logger.info("=== Comprehensive Comparative Evaluation Results ===")
    logger.info(f"Baseline In-Dist F1: {baseline_report['in_distribution_test_metrics']['f1']} | ROC-AUC: {baseline_report['in_distribution_test_metrics']['roc_auc']}")
    logger.info(f"Advanced In-Dist F1: {adv_in_metrics['f1']} | ROC-AUC: {adv_in_metrics['roc_auc']} | Brier: {adv_in_metrics['brier_score']}")
    logger.info(f"Baseline Cross-Dataset F1: {baseline_report['cross_dataset_test_metrics']['f1']} | ROC-AUC: {baseline_report['cross_dataset_test_metrics']['roc_auc']}")
    logger.info(f"Advanced Cross-Dataset F1: {adv_cross_metrics['f1']} | ROC-AUC: {adv_cross_metrics['roc_auc']} | Brier: {adv_cross_metrics['brier_score']}")
    logger.info(f"Phishing Recall (In-Dist): {phish_recall_in:.4f} | Phishing Recall (Cross-Dataset): {phish_recall_cross:.4f}")


if __name__ == "__main__":
    evaluate_all()
