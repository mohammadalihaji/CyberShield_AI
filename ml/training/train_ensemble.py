import os
import sys
import logging
from pathlib import Path
import numpy as np
import pandas as pd
from sklearn.model_selection import GroupShuffleSplit
from sklearn.ensemble import RandomForestClassifier
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import classification_report, roc_auc_score, accuracy_score, precision_score, recall_score, f1_score, brier_score_loss, confusion_matrix
import joblib

from ml.config import DATASET_DIR, MODEL_DIR, RANDOM_STATE, N_ESTIMATORS, CALIBRATION_METHOD
from ml.models.ensemble_model import EnsembleSecurityModel
from ml.models.model_registry import ModelRegistry
from ml.features.feature_schema import COMBINED_FEATURE_NAMES, URL_FEATURE_NAMES, PAGE_FEATURE_NAMES, get_schema_metadata
from ml.features.url_features import extract_base_domain

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def run_training():
    dataset_file = DATASET_DIR / "All_Features_threshold90.xlsx"
    if not dataset_file.exists():
        print("CompPhish V4 dataset file All_Features_threshold90.xlsx not found.")
        return

    print("Loading CompPhish V4 dataset for Ensemble Model Training & Calibration...")
    df = pd.read_excel(dataset_file)

    # Domain-aware grouping
    df["_extracted_domain"] = df["url"].apply(lambda u: extract_base_domain(str(u).split("/")[2] if "//" in str(u) else str(u)))

    gss_test = GroupShuffleSplit(n_splits=1, test_size=0.15, random_state=RANDOM_STATE)
    train_val_idx, test_idx = next(gss_test.split(df, groups=df["_extracted_domain"]))

    df_train_val = df.iloc[train_val_idx].copy()
    df_test = df.iloc[test_idx].copy()

    gss_val = GroupShuffleSplit(n_splits=1, test_size=0.1765, random_state=RANDOM_STATE)
    train_idx, val_idx = next(gss_val.split(df_train_val, groups=df_train_val["_extracted_domain"]))

    df_train = df_train_val.iloc[train_idx].copy()
    df_val = df_train_val.iloc[val_idx].copy()

    # Features and labels for full 70-feature model
    X_train_all = df_train[COMBINED_FEATURE_NAMES].values.astype(np.float32)
    y_train = df_train["label"].values.astype(int)

    X_val_all = df_val[COMBINED_FEATURE_NAMES].values.astype(np.float32)
    y_val = df_val["label"].values.astype(int)

    X_test_all = df_test[COMBINED_FEATURE_NAMES].values.astype(np.float32)
    y_test = df_test["label"].values.astype(int)

    print(f"Training Combined Ensemble Base Classifier on {len(X_train_all)} samples (70 features)...")
    base_ensemble = RandomForestClassifier(n_estimators=N_ESTIMATORS, max_depth=20, random_state=RANDOM_STATE, class_weight="balanced", n_jobs=-1)
    base_ensemble.fit(X_train_all, y_train)

    print(f"Calibrating Probabilities using {CALIBRATION_METHOD} calibration on {len(X_val_all)} validation samples...")
    calibrator = CalibratedClassifierCV(estimator=base_ensemble, method=CALIBRATION_METHOD, cv="prefit")
    calibrator.fit(X_val_all, y_val)

    # Evaluation on holdout test set
    probas = calibrator.predict_proba(X_test_all)[:, 1]
    preds = (probas >= 0.5).astype(int)

    auc = roc_auc_score(y_test, probas)
    acc = accuracy_score(y_test, preds)
    prec = precision_score(y_test, preds)
    rec = recall_score(y_test, preds)
    f1 = f1_score(y_test, preds)
    brier = brier_score_loss(y_test, probas)
    
    cm = confusion_matrix(y_test, preds)
    tn, fp, fn, tp = cm.ravel()
    fpr = fp / (fp + tn)
    fnr = fn / (fn + tp)

    print(f"\n================ CALIBRATED ENSEMBLE METRICS ================")
    print(f"Test ROC-AUC        : {auc:.4f}")
    print(f"Test Accuracy       : {acc:.4f} ({acc*100:.2f}%)")
    print(f"Test Precision      : {prec:.4f}")
    print(f"Test Recall         : {rec:.4f}")
    print(f"Test F1-Score       : {f1:.4f}")
    print(f"Brier Calibration   : {brier:.4f}")
    print(f"False Positive Rate : {fpr:.4f} ({fpr*100:.2f}%)")
    print(f"False Negative Rate : {fnr:.4f} ({fnr*100:.2f}%)")
    print(f"Confusion Matrix    : TN={tn}, FP={fp}, FN={fn}, TP={tp}")
    print("==============================================================\n")
    print("Detailed Classification Report:")
    print(classification_report(y_test, preds, target_names=["Legitimate (0)", "Phishing (1)"]))

    # Wrap in EnsembleSecurityModel
    ensemble_model = EnsembleSecurityModel(url_weight=0.45, page_weight=0.55, calibrator=calibrator)

    registry = ModelRegistry(MODEL_DIR)
    models = registry.load_models()
    url_model = models.get("url_model")
    page_model = models.get("page_model")
    schema_meta = get_schema_metadata()

    registry.save_models(
        url_model=url_model,
        page_model=page_model,
        ensemble_model=calibrator,  # Store calibrated pipeline for prediction
        calibrator=calibrator,
        schema_metadata=schema_meta,
        training_metrics={
            "ensemble_roc_auc": float(auc),
            "ensemble_accuracy": float(acc),
            "ensemble_precision": float(prec),
            "ensemble_recall": float(rec),
            "ensemble_f1": float(f1),
            "brier_score_loss": float(brier),
            "false_positive_rate": float(fpr),
            "false_negative_rate": float(fnr),
            "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)}
        },
        dataset_info={
            "dataset": "CompPhish Version 4",
            "total_samples": len(df),
            "train_samples": len(X_train_all),
            "val_samples": len(X_val_all),
            "test_samples": len(X_test_all),
            "total_features": len(COMBINED_FEATURE_NAMES),
            "url_features": len(URL_FEATURE_NAMES),
            "page_features": len(PAGE_FEATURE_NAMES),
            "domain_overlap": 0
        }
    )
    print("All production model artifacts and metrics successfully persisted.")


if __name__ == "__main__":
    run_training()
