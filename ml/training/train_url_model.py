import sys
import logging
from pathlib import Path
import numpy as np
import pandas as pd
from sklearn.metrics import classification_report, roc_auc_score

from ml.config import DATASET_DIR, MODEL_DIR
from ml.dataset_inspector import DatasetInspector
from ml.dataset_loader import DatasetLoader
from ml.models.url_model import URLSecurityModel
from ml.models.model_registry import ModelRegistry
from ml.features.url_features import extract_url_features
from ml.features.feature_schema import URL_FEATURE_NAMES, dict_to_vector, get_schema_metadata

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def run_training():
    inspector = DatasetInspector(DATASET_DIR)
    files = inspector.find_dataset_files()
    
    if not files:
        print("============================================================")
        print("CompPhish V4 dataset not found in data/compPhish_v4/.")
        print("Training is intentionally skipped.")
        print("Please place CompPhish V4 in data/compPhish_v4/ and confirm.")
        print("============================================================")
        return

    print("CompPhish V4 dataset detected. Starting URL model training pipeline...")
    loader = DatasetLoader(DATASET_DIR)
    df = loader.load_raw_dataset()
    if df is None:
        print("Failed to load tabular data.")
        return

    inspection = inspector.inspect()
    url_col = inspection.get("detected_url")
    label_col = inspection.get("detected_label")

    if not url_col or not label_col:
        print(f"Could not automatically detect URL ({url_col}) or Label ({label_col}) column.")
        return

    print(f"Splitting dataset domain-aware on URL column: {url_col}...")
    df_train, df_val, df_test = loader.split_domain_aware(df, url_col=url_col)

    print("Extracting URL features for training set...")
    X_train = np.array([dict_to_vector(extract_url_features(str(u)), URL_FEATURE_NAMES) for u in df_train[url_col]])
    y_train = df_train[label_col].values.astype(int)

    print("Extracting URL features for test set...")
    X_test = np.array([dict_to_vector(extract_url_features(str(u)), URL_FEATURE_NAMES) for u in df_test[url_col]])
    y_test = df_test[label_col].values.astype(int)

    print("Fitting URL Security Model (RandomForest)...")
    model = URLSecurityModel()
    model.fit(X_train, y_train)

    preds = model.model.predict(X_test)
    probas = model.predict_proba(X_test)[:, 1] if model.predict_proba(X_test).shape[1] >= 2 else model.predict_proba(X_test)[:, 0]
    
    auc = roc_auc_score(y_test, probas)
    print(f"\nTest ROC-AUC: {auc:.4f}")
    print("\nClassification Report:")
    print(classification_report(y_test, preds))

    registry = ModelRegistry(MODEL_DIR)
    schema_meta = get_schema_metadata()
    registry.save_models(
        url_model=model,
        page_model=None,
        ensemble_model=None,
        calibrator=None,
        schema_metadata=schema_meta,
        training_metrics={"url_model_roc_auc": float(auc)},
        dataset_info={"train_samples": len(X_train), "test_samples": len(X_test)}
    )
    print("URL model trained and saved successfully.")


if __name__ == "__main__":
    run_training()
