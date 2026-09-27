import os
import sys
import json
import logging
from pathlib import Path
import pandas as pd
import numpy as np
import joblib

from sklearn.model_selection import StratifiedKFold
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.calibration import CalibratedClassifierCV, calibration_curve
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, average_precision_score, brier_score_loss, confusion_matrix
)

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ml.email.config import (
    PROCESSED_DATA_DIR,
    ARTIFACTS_DIR,
    MODEL_DIR,
    META_MODEL_FILE,
    CALIBRATOR_FILE,
    METADATA_FILE,
    CALIBRATION_CURVE_FILE,
    MODEL_VERSION,
    FEATURE_SCHEMA_VERSION,
    TRANSFORMER_MODEL_NAME,
    N_OOF_FOLDS,
    RANDOM_STATE
)
from ml.email.feature_extractor import STRUCTURED_FEATURE_NAMES

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("train_oof_stacking")


def calculate_ece(y_true: np.ndarray, y_prob: np.ndarray, n_bins: int = 10) -> float:
    """Computes Expected Calibration Error (ECE)."""
    bin_boundaries = np.linspace(0, 1, n_bins + 1)
    ece = 0.0
    for i in range(n_bins):
        bin_lower, bin_upper = bin_boundaries[i], bin_boundaries[i + 1]
        mask = (y_prob >= bin_lower) & (y_prob < bin_upper) if i < n_bins - 1 else (y_prob >= bin_lower) & (y_prob <= bin_upper)
        if np.sum(mask) > 0:
            bin_acc = np.mean(y_true[mask])
            bin_conf = np.mean(y_prob[mask])
            ece += np.sum(mask) * np.abs(bin_acc - bin_conf)
    return float(ece / len(y_true))


def assemble_meta_features(p_text: np.ndarray, p_struct: np.ndarray, p_url: np.ndarray) -> np.ndarray:
    """
    Constructs multi-modal meta-feature matrix for the stacking ensemble.
    Includes base probabilities and high-order interaction / risk-dominance signals.
    """
    p_text = np.clip(p_text, 1e-6, 1.0 - 1e-6)
    p_struct = np.clip(p_struct, 1e-6, 1.0 - 1e-6)
    p_url = np.clip(p_url, 1e-6, 1.0 - 1e-6)

    max_signal = np.maximum(p_text, p_struct)
    mean_signal = (p_text + p_struct + p_url) / 3.0
    text_struct_interaction = p_text * p_struct
    discrepancy = np.abs(p_text - p_struct)

    meta_matrix = np.column_stack([
        p_text,
        p_struct,
        p_url,
        max_signal,
        mean_signal,
        text_struct_interaction,
        discrepancy
    ])
    return meta_matrix.astype(np.float32)


def run_oof_stacking_and_calibration():
    logger.info("Loading cached feature representations...")
    cache_dir = ARTIFACTS_DIR / "embedding_cache"
    struct_cache_dir = ARTIFACTS_DIR / "structured_cache"

    df_train = pd.read_parquet(PROCESSED_DATA_DIR / "train.parquet")
    df_val = pd.read_parquet(PROCESSED_DATA_DIR / "val.parquet")
    df_test_in = pd.read_parquet(PROCESSED_DATA_DIR / "test_in_dist.parquet")
    df_test_cross = pd.read_parquet(PROCESSED_DATA_DIR / "test_cross_dataset.parquet")

    label_map = {"ham": 0, "spam": 1, "phishing": 2}
    y_train_bin = (df_train["label"].map(label_map).values > 0).astype(int)
    y_val_bin = (df_val["label"].map(label_map).values > 0).astype(int)
    y_test_in_bin = (df_test_in["label"].map(label_map).values > 0).astype(int)
    y_test_cross_bin = (df_test_cross["label"].map(label_map).values > 0).astype(int)

    X_train_emb = np.load(cache_dir / "train_embeddings.npy")
    X_val_emb = np.load(cache_dir / "val_embeddings.npy")
    X_test_in_emb = np.load(cache_dir / "test_in_embeddings.npy")
    X_test_cross_emb = np.load(cache_dir / "test_cross_embeddings.npy")

    X_train_struct = np.load(struct_cache_dir / "train_struct_features.npy")
    X_val_struct = np.load(struct_cache_dir / "val_struct_features.npy")
    X_test_in_struct = np.load(struct_cache_dir / "test_in_struct_features.npy")
    X_test_cross_struct = np.load(struct_cache_dir / "test_cross_struct_features.npy")

    # URL Risk feature index in STRUCTURED_FEATURE_NAMES
    url_risk_idx = STRUCTURED_FEATURE_NAMES.index("email_max_url_risk")
    url_risk_train = X_train_struct[:, url_risk_idx]
    url_risk_val = X_val_struct[:, url_risk_idx]
    url_risk_test_in = X_test_in_struct[:, url_risk_idx]
    url_risk_test_cross = X_test_cross_struct[:, url_risk_idx]

    logger.info(f"Generating {N_OOF_FOLDS}-Fold Out-Of-Fold predictions on training set...")
    skf = StratifiedKFold(n_splits=N_OOF_FOLDS, shuffle=True, random_state=RANDOM_STATE)

    oof_p_text = np.zeros(len(y_train_bin), dtype=np.float32)
    oof_p_struct = np.zeros(len(y_train_bin), dtype=np.float32)

    for fold, (train_idx, val_idx) in enumerate(skf.split(X_train_emb, y_train_bin)):
        logger.info(f"  Processing Fold {fold + 1}/{N_OOF_FOLDS}...")
        # Text fold model
        clf_text_fold = LogisticRegression(C=1.0, max_iter=1000, random_state=RANDOM_STATE, class_weight="balanced")
        clf_text_fold.fit(X_train_emb[train_idx], y_train_bin[train_idx])
        oof_p_text[val_idx] = clf_text_fold.predict_proba(X_train_emb[val_idx])[:, 1]

        # Structured fold model
        clf_struct_fold = HistGradientBoostingClassifier(max_iter=150, random_state=RANDOM_STATE, class_weight="balanced")
        clf_struct_fold.fit(X_train_struct[train_idx], y_train_bin[train_idx])
        oof_p_struct[val_idx] = clf_struct_fold.predict_proba(X_train_struct[val_idx])[:, 1]

    # Build OOF Meta-Feature Matrix
    X_meta_train = assemble_meta_features(oof_p_text, oof_p_struct, url_risk_train)

    logger.info(f"OOF Meta-Feature shape: {X_meta_train.shape}")

    # Train Full Base Models on full training set to produce test/val predictions
    logger.info("Training full base models...")
    full_text_model = LogisticRegression(C=1.0, max_iter=1000, random_state=RANDOM_STATE, class_weight="balanced")
    full_text_model.fit(X_train_emb, y_train_bin)

    full_struct_model = HistGradientBoostingClassifier(max_iter=200, random_state=RANDOM_STATE, class_weight="balanced")
    full_struct_model.fit(X_train_struct, y_train_bin)

    # Generate meta features for Validation and Tests
    p_text_val = full_text_model.predict_proba(X_val_emb)[:, 1]
    p_struct_val = full_struct_model.predict_proba(X_val_struct)[:, 1]
    X_meta_val = assemble_meta_features(p_text_val, p_struct_val, url_risk_val)

    p_text_test_in = full_text_model.predict_proba(X_test_in_emb)[:, 1]
    p_struct_test_in = full_struct_model.predict_proba(X_test_in_struct)[:, 1]
    X_meta_test_in = assemble_meta_features(p_text_test_in, p_struct_test_in, url_risk_test_in)

    p_text_test_cross = full_text_model.predict_proba(X_test_cross_emb)[:, 1]
    p_struct_test_cross = full_struct_model.predict_proba(X_test_cross_struct)[:, 1]
    X_meta_test_cross = assemble_meta_features(p_text_test_cross, p_struct_test_cross, url_risk_test_cross)

    # Fit Stacking Meta-Learner on Out-Of-Fold predictions
    logger.info("Fitting Stacking Ensemble Meta-Learner (LogisticRegression on OOF predictions)...")
    meta_clf = LogisticRegression(C=1.0, max_iter=1000, random_state=RANDOM_STATE)
    meta_clf.fit(X_meta_train, y_train_bin)

    raw_val_probs = meta_clf.predict_proba(X_meta_val)[:, 1]

    # Evaluate Calibration: Platt Sigmoid vs Isotonic Regression on Validation
    logger.info("Fitting and evaluating probability calibrator (Platt Scaling)...")
    calibrator = CalibratedClassifierCV(estimator=meta_clf, method="sigmoid", cv="prefit")
    calibrator.fit(X_meta_val, y_val_bin)

    cal_val_probs = calibrator.predict_proba(X_meta_val)[:, 1]
    cal_test_in_probs = calibrator.predict_proba(X_meta_test_in)[:, 1]
    cal_test_cross_probs = calibrator.predict_proba(X_meta_test_cross)[:, 1]

    brier_raw = brier_score_loss(y_val_bin, raw_val_probs)
    brier_cal = brier_score_loss(y_val_bin, cal_val_probs)
    ece_val = calculate_ece(y_val_bin, cal_val_probs)
    ece_test_in = calculate_ece(y_test_in_bin, cal_test_in_probs)

    logger.info(f"Validation Brier Score: Raw={brier_raw:.4f} -> Calibrated={brier_cal:.4f}")
    logger.info(f"Validation ECE: {ece_val:.4f}, Test In-Dist ECE: {ece_test_in:.4f}")

    # Reliability Curve computation
    prob_true, prob_pred = calibration_curve(y_test_in_bin, cal_test_in_probs, n_bins=10)
    curve_data = {
        "true_probabilities": [round(float(p), 4) for p in prob_true],
        "pred_probabilities": [round(float(p), 4) for p in prob_pred]
    }
    with open(MODEL_DIR / CALIBRATION_CURVE_FILE, "w", encoding="utf-8") as f:
        json.dump(curve_data, f, indent=2)

    # Save Meta Model & Calibrator
    joblib.dump(meta_clf, MODEL_DIR / META_MODEL_FILE)
    joblib.dump(calibrator, MODEL_DIR / CALIBRATOR_FILE)

    # Final Model Metadata
    metadata = {
        "model_version": MODEL_VERSION,
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "transformer_model_name": TRANSFORMER_MODEL_NAME,
        "meta_model_type": "LogisticRegression Stacking Meta-Learner",
        "calibration_method": "Platt Scaling (Sigmoid)",
        "brier_score_loss": round(float(brier_cal), 4),
        "expected_calibration_error": round(float(ece_test_in), 4),
        "structured_feature_count": len(STRUCTURED_FEATURE_NAMES),
        "oof_folds": N_OOF_FOLDS
    }
    with open(MODEL_DIR / METADATA_FILE, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    logger.info("OOF Stacking, Probability Calibration, and Model Metadata completed successfully.")


if __name__ == "__main__":
    run_oof_stacking_and_calibration()
