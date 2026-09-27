import sys
import json
import logging
from pathlib import Path
import pandas as pd
import numpy as np
import joblib

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, average_precision_score, confusion_matrix, brier_score_loss
)

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from ml.email.config import PROCESSED_DATA_DIR, ARTIFACTS_DIR, RANDOM_STATE

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("train_baseline")


def prepare_text_series(df: pd.DataFrame) -> pd.Series:
    """Combines subject and plain_text into standard text input."""
    subj = df["subject"].fillna("").astype(str)
    body = df["plain_text"].fillna("").astype(str)
    return "[SUBJECT] " + subj + " [BODY] " + body


def train_and_evaluate_baseline():
    logger.info("Loading processed dataset splits...")
    df_train = pd.read_parquet(PROCESSED_DATA_DIR / "train.parquet")
    df_val = pd.read_parquet(PROCESSED_DATA_DIR / "val.parquet")
    df_test_in = pd.read_parquet(PROCESSED_DATA_DIR / "test_in_dist.parquet")
    df_test_cross = pd.read_parquet(PROCESSED_DATA_DIR / "test_cross_dataset.parquet")

    # Binary and 3-class target mapping:
    # 0 = Ham (Legitimate), 1 = Spam, 2 = Phishing
    # Malicious binary target: 0 = Ham, 1 = Malicious (Spam or Phishing)
    label_map = {"ham": 0, "spam": 1, "phishing": 2}
    
    y_train_3 = df_train["label"].map(label_map).values
    y_val_3 = df_val["label"].map(label_map).values
    y_test_in_3 = df_test_in["label"].map(label_map).values
    y_test_cross_3 = df_test_cross["label"].map(label_map).values

    # Binary labels for malicious vs ham
    y_train_bin = (y_train_3 > 0).astype(int)
    y_val_bin = (y_val_3 > 0).astype(int)
    y_test_in_bin = (y_test_in_3 > 0).astype(int)
    y_test_cross_bin = (y_test_cross_3 > 0).astype(int)

    X_train_text = prepare_text_series(df_train)
    X_val_text = prepare_text_series(df_val)
    X_test_in_text = prepare_text_series(df_test_in)
    X_test_cross_text = prepare_text_series(df_test_cross)

    logger.info("Extracting TF-IDF features (max_features=5000)...")
    tfidf = TfidfVectorizer(max_features=5000, ngram_range=(1, 2), stop_words="english", sublinear_tf=True)
    X_train_vec = tfidf.fit_transform(X_train_text)
    X_val_vec = tfidf.transform(X_val_text)
    X_test_in_vec = tfidf.transform(X_test_in_text)
    X_test_cross_vec = tfidf.transform(X_test_cross_text)

    # 1. Train Binary Malicious Detector (TF-IDF + LR)
    logger.info("Fitting Baseline Binary Classifier (TF-IDF + Logistic Regression)...")
    clf_bin = LogisticRegression(max_iter=1000, random_state=RANDOM_STATE, class_weight="balanced")
    clf_bin.fit(X_train_vec, y_train_bin)

    # 2. Train 3-Class Classifier (TF-IDF + LR)
    logger.info("Fitting Baseline 3-Class Classifier...")
    clf_multi = LogisticRegression(max_iter=1000, random_state=RANDOM_STATE, class_weight="balanced")
    clf_multi.fit(X_train_vec, y_train_3)

    def compute_eval_metrics(clf, X, y_true, name=""):
        probs = clf.predict_proba(X)
        preds = clf.predict(X)
        
        prob_mal = probs[:, 1] if probs.shape[1] == 2 else probs[:, 1:].sum(axis=1)
        acc = float(accuracy_score(y_true, preds))
        prec = float(precision_score(y_true, preds, zero_division=0))
        rec = float(recall_score(y_true, preds, zero_division=0))
        f1 = float(f1_score(y_true, preds, zero_division=0))
        roc = float(roc_auc_score(y_true, prob_mal))
        pr_auc = float(average_precision_score(y_true, prob_mal))
        brier = float(brier_score_loss(y_true, prob_mal))
        cm = confusion_matrix(y_true, preds)
        tn, fp, fn, tp = cm.ravel()
        fpr = float(fp / max(tn + fp, 1))
        fnr = float(fn / max(tp + fn, 1))

        res = {
            "accuracy": round(acc, 4),
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1": round(f1, 4),
            "roc_auc": round(roc, 4),
            "pr_auc": round(pr_auc, 4),
            "brier_score": round(brier, 4),
            "false_positive_rate": round(fpr, 4),
            "false_negative_rate": round(fnr, 4),
            "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)}
        }
        logger.info(f"[{name}] Acc: {res['accuracy']}, Rec: {res['recall']}, Prec: {res['precision']}, F1: {res['f1']}, ROC: {res['roc_auc']}, PR-AUC: {res['pr_auc']}, FPR: {res['false_positive_rate']}")
        return res

    logger.info("=== Baseline Evaluation (Binary Malicious: Ham vs Spam/Phishing) ===")
    val_metrics = compute_eval_metrics(clf_bin, X_val_vec, y_val_bin, "Validation")
    test_in_metrics = compute_eval_metrics(clf_bin, X_test_in_vec, y_test_in_bin, "In-Distribution Test")
    test_cross_metrics = compute_eval_metrics(clf_bin, X_test_cross_vec, y_test_cross_bin, "Cross-Dataset Test")

    metrics_output = {
        "model_name": "Baseline (TF-IDF + Logistic Regression)",
        "feature_count": 5000,
        "validation_metrics": val_metrics,
        "in_distribution_test_metrics": test_in_metrics,
        "cross_dataset_test_metrics": test_cross_metrics
    }

    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    with open(ARTIFACTS_DIR / "baseline_metrics.json", "w", encoding="utf-8") as f:
        json.dump(metrics_output, f, indent=2)

    joblib.dump({"tfidf": tfidf, "model_bin": clf_bin, "model_multi": clf_multi}, ARTIFACTS_DIR / "baseline_model.joblib")
    logger.info("Baseline training and evaluation saved successfully.")


if __name__ == "__main__":
    train_and_evaluate_baseline()
