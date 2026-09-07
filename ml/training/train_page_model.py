import sys
import logging
from pathlib import Path
import numpy as np
import pandas as pd
from sklearn.metrics import classification_report, roc_auc_score

from ml.config import DATASET_DIR, MODEL_DIR
from ml.dataset_inspector import DatasetInspector
from ml.dataset_loader import DatasetLoader
from ml.models.page_model import PageSecurityModel
from ml.models.model_registry import ModelRegistry
from ml.features.html_features import extract_html_features
from ml.features.feature_schema import PAGE_FEATURE_NAMES, dict_to_vector, get_schema_metadata

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def run_training():
    inspector = DatasetInspector(DATASET_DIR)
    files = inspector.find_dataset_files()
    
    if not files:
        print("============================================================")
        print("CompPhish V4 dataset not found in data/compPhish_v4/.")
        print("Training is intentionally skipped.")
        print("============================================================")
        return

    print("CompPhish V4 dataset detected. Starting Page model training pipeline...")
    loader = DatasetLoader(DATASET_DIR)
    df = loader.load_raw_dataset()
    if df is None:
        return

    inspection = inspector.inspect()
    url_col = inspection.get("detected_url")
    html_col = inspection.get("detected_html")
    label_col = inspection.get("detected_label")

    if not label_col:
        print("Label column not detected.")
        return

    if not html_col:
        print("HTML column not detected in dataset. Page model training requires HTML content.")
        return

    print(f"Splitting dataset domain-aware on URL column: {url_col}...")
    df_train, df_val, df_test = loader.split_domain_aware(df, url_col=url_col or html_col)

    print("Extracting HTML/Page features for training set...")
    X_train = np.array([dict_to_vector(extract_html_features(str(h), str(u)), PAGE_FEATURE_NAMES) for h, u in zip(df_train[html_col], df_train.get(url_col, [""] * len(df_train)))])
    y_train = df_train[label_col].values.astype(int)

    print("Extracting HTML/Page features for test set...")
    X_test = np.array([dict_to_vector(extract_html_features(str(h), str(u)), PAGE_FEATURE_NAMES) for h, u in zip(df_test[html_col], df_test.get(url_col, [""] * len(df_test)))])
    y_test = df_test[label_col].values.astype(int)

    print("Fitting Page Security Model (RandomForest)...")
    model = PageSecurityModel()
    model.fit(X_train, y_train)

    preds = model.model.predict(X_test)
    probas = model.predict_proba(X_test)[:, 1] if model.predict_proba(X_test).shape[1] >= 2 else model.predict_proba(X_test)[:, 0]
    
    auc = roc_auc_score(y_test, probas)
    print(f"\nTest ROC-AUC: {auc:.4f}")
    print("\nClassification Report:")
    print(classification_report(y_test, preds))

    registry = ModelRegistry(MODEL_DIR)
    models = registry.load_models()
    url_model = models.get("url_model")
    schema_meta = get_schema_metadata()

    registry.save_models(
        url_model=url_model,
        page_model=model,
        ensemble_model=None,
        calibrator=None,
        schema_metadata=schema_meta,
        training_metrics={"page_model_roc_auc": float(auc)},
        dataset_info={"train_samples": len(X_train), "test_samples": len(X_test)}
    )
    print("Page model trained and saved successfully.")


if __name__ == "__main__":
    run_training()
