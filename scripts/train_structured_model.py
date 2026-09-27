import os
import sys
import json
import logging
from pathlib import Path
import pandas as pd
import numpy as np
import joblib

from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, average_precision_score

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ml.email.config import (
    PROCESSED_DATA_DIR,
    ARTIFACTS_DIR,
    MODEL_DIR,
    STRUCTURED_MODEL_FILE,
    FEATURE_SCHEMA_FILE,
    RANDOM_STATE
)
from ml.email.schema import EmailRecord, AttachmentMetadata
from ml.email.feature_extractor import EmailFeatureExtractor, STRUCTURED_FEATURE_NAMES

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("train_structured_model")



def extract_features_from_df(df: pd.DataFrame, extractor: EmailFeatureExtractor) -> np.ndarray:
    vectors = []
    for _, row in df.iterrows():
        # Reconstruct attachments
        attach_list = []
        attach_raw = row.get("attachments_json")
        if attach_raw and isinstance(attach_raw, str):
            try:
                for a in json.loads(attach_raw):
                    attach_list.append(AttachmentMetadata(**a))
            except Exception:
                pass

        # Reconstruct URLs
        urls_list = []
        urls_raw = row.get("urls_json")
        if urls_raw and isinstance(urls_raw, str):
            try:
                urls_list = json.loads(urls_raw)
            except Exception:
                pass

        rec = EmailRecord(
            id=str(row.get("id", "")),
            source_dataset=str(row.get("source_dataset", "")),
            label=str(row.get("label", "")),
            subject=str(row.get("subject", "") or ""),
            plain_text=str(row.get("plain_text", "") or ""),
            html=str(row.get("html", "") or ""),
            from_address=str(row.get("from_address", "") or ""),
            from_domain=str(row.get("from_domain", "") or ""),
            reply_to=str(row.get("reply_to", "") or ""),
            reply_to_domain=str(row.get("reply_to_domain", "") or ""),
            return_path=str(row.get("return_path", "") or ""),
            return_path_domain=str(row.get("return_path_domain", "") or ""),
            authentication_results=str(row.get("authentication_results", "") or ""),
            spf_verdict=str(row.get("spf_verdict", "none")),
            dkim_verdict=str(row.get("dkim_verdict", "none")),
            dmarc_verdict=str(row.get("dmarc_verdict", "none")),
            message_id=str(row.get("message_id", "") or ""),
            date=str(row.get("date", "") or ""),
            urls=urls_list,
            attachments=attach_list
        )
        vec, _ = extractor.extract_vector(rec)
        vectors.append(vec)
    return np.array(vectors, dtype=np.float32)


def train_structured_model():
    logger.info("Loading processed dataset splits...")
    df_train = pd.read_parquet(PROCESSED_DATA_DIR / "train.parquet")
    df_val = pd.read_parquet(PROCESSED_DATA_DIR / "val.parquet")
    df_test_in = pd.read_parquet(PROCESSED_DATA_DIR / "test_in_dist.parquet")
    df_test_cross = pd.read_parquet(PROCESSED_DATA_DIR / "test_cross_dataset.parquet")

    label_map = {"ham": 0, "spam": 1, "phishing": 2}
    y_train_bin = (df_train["label"].map(label_map).values > 0).astype(int)
    y_val_bin = (df_val["label"].map(label_map).values > 0).astype(int)
    y_test_in_bin = (df_test_in["label"].map(label_map).values > 0).astype(int)
    y_test_cross_bin = (df_test_cross["label"].map(label_map).values > 0).astype(int)

    y_train_3 = df_train["label"].map(label_map).values

    extractor = EmailFeatureExtractor()

    # Cached features
    cache_dir = ARTIFACTS_DIR / "structured_cache"
    cache_dir.mkdir(parents=True, exist_ok=True)
    
    train_feat_file = cache_dir / "train_struct_features.npy"
    val_feat_file = cache_dir / "val_struct_features.npy"
    test_in_feat_file = cache_dir / "test_in_struct_features.npy"
    test_cross_feat_file = cache_dir / "test_cross_struct_features.npy"

    if train_feat_file.exists():
        logger.info("Loading cached structured features...")
        X_train = np.load(train_feat_file)
    else:
        logger.info("Extracting structured features for train split...")
        X_train = extract_features_from_df(df_train, extractor)
        np.save(train_feat_file, X_train)

    if val_feat_file.exists():
        X_val = np.load(val_feat_file)
    else:
        logger.info("Extracting structured features for val split...")
        X_val = extract_features_from_df(df_val, extractor)
        np.save(val_feat_file, X_val)

    if test_in_feat_file.exists():
        X_test_in = np.load(test_in_feat_file)
    else:
        logger.info("Extracting structured features for test_in split...")
        X_test_in = extract_features_from_df(df_test_in, extractor)
        np.save(test_in_feat_file, X_test_in)

    if test_cross_feat_file.exists():
        X_test_cross = np.load(test_cross_feat_file)
    else:
        logger.info("Extracting structured features for test_cross split...")
        X_test_cross = extract_features_from_df(df_test_cross, extractor)
        np.save(test_cross_feat_file, X_test_cross)

    logger.info(f"Structured feature matrix shape: {X_train.shape} ({len(STRUCTURED_FEATURE_NAMES)} features)")

    # Benchmark: HistGradientBoostingClassifier vs RandomForestClassifier
    logger.info("Fitting HistGradientBoostingClassifier...")
    hgb = HistGradientBoostingClassifier(
        max_iter=200,
        learning_rate=0.08,
        max_leaf_nodes=31,
        random_state=RANDOM_STATE,
        class_weight="balanced"
    )
    hgb.fit(X_train, y_train_bin)
    val_probs_hgb = hgb.predict_proba(X_val)[:, 1]
    val_auc_hgb = roc_auc_score(y_val_bin, val_probs_hgb)

    logger.info("Fitting RandomForestClassifier...")
    rf = RandomForestClassifier(
        n_estimators=150,
        max_depth=16,
        random_state=RANDOM_STATE,
        class_weight="balanced",
        n_jobs=-1
    )
    rf.fit(X_train, y_train_bin)
    val_probs_rf = rf.predict_proba(X_val)[:, 1]
    val_auc_rf = roc_auc_score(y_val_bin, val_probs_rf)

    logger.info(f"HistGradientBoosting Val ROC-AUC: {val_auc_hgb:.4f}")
    logger.info(f"RandomForest Val ROC-AUC: {val_auc_rf:.4f}")

    best_model = hgb if val_auc_hgb >= val_auc_rf else rf

    # Fit 3-Class structured model
    hgb_3class = HistGradientBoostingClassifier(
        max_iter=200,
        learning_rate=0.08,
        random_state=RANDOM_STATE,
        class_weight="balanced"
    )
    hgb_3class.fit(X_train, y_train_3)

    test_in_probs = best_model.predict_proba(X_test_in)[:, 1]
    test_cross_probs = best_model.predict_proba(X_test_cross)[:, 1]

    metrics = {
        "best_model_type": type(best_model).__name__,
        "feature_count": len(STRUCTURED_FEATURE_NAMES),
        "val_roc_auc": round(float(val_auc_hgb), 4),
        "test_in_roc_auc": round(float(roc_auc_score(y_test_in_bin, test_in_probs)), 4),
        "test_in_pr_auc": round(float(average_precision_score(y_test_in_bin, test_in_probs)), 4),
        "test_cross_roc_auc": round(float(roc_auc_score(y_test_cross_bin, test_cross_probs)), 4),
        "test_cross_pr_auc": round(float(average_precision_score(y_test_cross_bin, test_cross_probs)), 4),
    }

    logger.info(f"Structured Model Test In-Dist ROC-AUC: {metrics['test_in_roc_auc']}")
    logger.info(f"Structured Model Test Cross-Dataset ROC-AUC: {metrics['test_cross_roc_auc']}")

    # Save structured model bundle & feature schema
    bundle = {
        "binary_model": best_model,
        "multi_model": hgb_3class,
        "feature_names": STRUCTURED_FEATURE_NAMES,
        "metrics": metrics
    }
    joblib.dump(bundle, MODEL_DIR / STRUCTURED_MODEL_FILE)

    with open(MODEL_DIR / FEATURE_SCHEMA_FILE, "w", encoding="utf-8") as f:
        json.dump({"feature_names": STRUCTURED_FEATURE_NAMES, "count": len(STRUCTURED_FEATURE_NAMES)}, f, indent=2)

    with open(ARTIFACTS_DIR / "structured_model_metrics.json", "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)

    logger.info(f"Structured model saved to {MODEL_DIR / STRUCTURED_MODEL_FILE}")


if __name__ == "__main__":
    train_structured_model()
