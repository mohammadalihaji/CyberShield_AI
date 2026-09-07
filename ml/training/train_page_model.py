import os
import sys
import logging
from pathlib import Path
import numpy as np
import pandas as pd
from sklearn.model_selection import GroupShuffleSplit
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, roc_auc_score, accuracy_score, precision_score, recall_score, f1_score
import joblib

from ml.config import DATASET_DIR, MODEL_DIR, RANDOM_STATE, N_ESTIMATORS
from ml.models.page_model import PageSecurityModel
from ml.models.model_registry import ModelRegistry
from ml.features.feature_schema import PAGE_FEATURE_NAMES, get_schema_metadata
from ml.features.url_features import extract_base_domain

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def run_training():
    dataset_file = DATASET_DIR / "All_Features_threshold90.xlsx"
    if not dataset_file.exists():
        print("CompPhish V4 dataset file All_Features_threshold90.xlsx not found.")
        return

    print("Loading CompPhish V4 dataset for Page Model Training...")
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

    # Features and labels
    X_train = df_train[PAGE_FEATURE_NAMES].values.astype(np.float32)
    y_train = df_train["label"].values.astype(int)

    X_test = df_test[PAGE_FEATURE_NAMES].values.astype(np.float32)
    y_test = df_test["label"].values.astype(int)

    print(f"Training Page Model on {len(X_train)} samples across {len(PAGE_FEATURE_NAMES)} Page features...")
    page_model = PageSecurityModel(n_estimators=N_ESTIMATORS, random_state=RANDOM_STATE)
    page_model.fit(X_train, y_train)

    probas = page_model.model.predict_proba(X_test)[:, 1]
    preds = (probas >= 0.5).astype(int)

    auc = roc_auc_score(y_test, probas)
    acc = accuracy_score(y_test, preds)
    prec = precision_score(y_test, preds)
    rec = recall_score(y_test, preds)
    f1 = f1_score(y_test, preds)

    print(f"\n================ PAGE MODEL METRICS ================")
    print(f"Test ROC-AUC  : {auc:.4f}")
    print(f"Test Accuracy : {acc:.4f}")
    print(f"Test Precision: {prec:.4f}")
    print(f"Test Recall   : {rec:.4f}")
    print(f"Test F1-Score : {f1:.4f}")
    print("====================================================\n")

    registry = ModelRegistry(MODEL_DIR)
    models = registry.load_models()
    url_model = models.get("url_model")
    schema_meta = get_schema_metadata()

    registry.save_models(
        url_model=url_model,
        page_model=page_model,
        ensemble_model=models.get("ensemble_model"),
        calibrator=models.get("calibrator"),
        schema_metadata=schema_meta,
        training_metrics={
            "page_roc_auc": float(auc),
            "page_accuracy": float(acc),
            "page_precision": float(prec),
            "page_recall": float(rec),
            "page_f1": float(f1)
        },
        dataset_info={
            "total_samples": len(df),
            "train_samples": len(X_train),
            "test_samples": len(X_test),
            "page_features": len(PAGE_FEATURE_NAMES)
        }
    )
    print("Page model artifacts saved successfully.")


if __name__ == "__main__":
    run_training()
