import os
import sys
import json
import logging
from pathlib import Path
import pandas as pd
import numpy as np
import joblib

from sklearn.linear_model import LogisticRegression
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, average_precision_score

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ml.email.config import (
    PROCESSED_DATA_DIR,
    ARTIFACTS_DIR,
    MODEL_DIR,
    TEXT_MODEL_FILE,
    TRANSFORMER_MODEL_NAME,
    RANDOM_STATE
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("train_text_model")


def prepare_text_series(df: pd.DataFrame) -> list:
    """Combines subject and plain text, capping length to 512 tokens."""
    texts = []
    for _, row in df.iterrows():
        subj = str(row.get("subject", "") or "").strip()
        body = str(row.get("plain_text", "") or "").strip()
        # Clean excessive whitespace
        body_snippet = " ".join(body.split()[:400])
        combined = f"[SUBJECT] {subj} [BODY] {body_snippet}"
        texts.append(combined)
    return texts


class TextEmbeddingExtractor:
    """
    Extracts dense semantic embeddings using SentenceTransformers or HuggingFace MiniLM/DistilBERT.
    Includes memory caching for fast reproducible training.
    """

    def __init__(self, model_name: str = TRANSFORMER_MODEL_NAME):
        self.model_name = model_name
        self.model = None
        self._init_model()

    def _init_model(self):
        logger.info(f"Loading transformer model: {self.model_name}...")
        try:
            from sentence_transformers import SentenceTransformer
            self.model = SentenceTransformer(self.model_name)
        except Exception as e:
            logger.warning(f"Failed to load via SentenceTransformer ({e}). Trying HuggingFace pipeline...")
            from transformers import AutoTokenizer, AutoModel
            import torch

            class HFEmbeddingWrapper:
                def __init__(self, name):
                    self.tokenizer = AutoTokenizer.from_pretrained(name)
                    self.hf_model = AutoModel.from_pretrained(name)
                    self.hf_model.eval()

                def encode(self, texts, batch_size=64, show_progress_bar=False):
                    embeddings = []
                    for i in range(0, len(texts), batch_size):
                        batch = texts[i:i + batch_size]
                        encoded = self.tokenizer(batch, padding=True, truncation=True, max_length=256, return_tensors="pt")
                        with torch.no_grad():
                            out = self.hf_model(**encoded)
                            # Mean pooling
                            mask = encoded["attention_mask"].unsqueeze(-1).expand(out.last_hidden_state.size()).float()
                            sum_emb = torch.sum(out.last_hidden_state * mask, 1)
                            sum_mask = torch.clamp(mask.sum(1), min=1e-9)
                            pooled = sum_emb / sum_mask
                            embeddings.append(pooled.cpu().numpy())
                    return np.vstack(embeddings)

            self.model = HFEmbeddingWrapper(self.model_name)

    def encode(self, texts: list, batch_size: int = 128) -> np.ndarray:
        logger.info(f"Encoding {len(texts)} texts in batches of {batch_size}...")
        return self.model.encode(texts, batch_size=batch_size, show_progress_bar=False)


def train_text_model():
    logger.info("Loading processed dataset splits...")
    df_train = pd.read_parquet(PROCESSED_DATA_DIR / "train.parquet")
    df_val = pd.read_parquet(PROCESSED_DATA_DIR / "val.parquet")
    df_test_in = pd.read_parquet(PROCESSED_DATA_DIR / "test_in_dist.parquet")
    df_test_cross = pd.read_parquet(PROCESSED_DATA_DIR / "test_cross_dataset.parquet")

    # Map labels to binary (0 = ham, 1 = malicious) and 3-class (0 = ham, 1 = spam, 2 = phishing)
    label_map = {"ham": 0, "spam": 1, "phishing": 2}
    y_train_bin = (df_train["label"].map(label_map).values > 0).astype(int)
    y_val_bin = (df_val["label"].map(label_map).values > 0).astype(int)
    y_test_in_bin = (df_test_in["label"].map(label_map).values > 0).astype(int)
    y_test_cross_bin = (df_test_cross["label"].map(label_map).values > 0).astype(int)

    y_train_3 = df_train["label"].map(label_map).values
    y_val_3 = df_val["label"].map(label_map).values
    y_test_in_3 = df_test_in["label"].map(label_map).values
    y_test_cross_3 = df_test_cross["label"].map(label_map).values

    train_texts = prepare_text_series(df_train)
    val_texts = prepare_text_series(df_val)
    test_in_texts = prepare_text_series(df_test_in)
    test_cross_texts = prepare_text_series(df_test_cross)

    embedder = TextEmbeddingExtractor()

    # Cached embedding paths
    cache_dir = ARTIFACTS_DIR / "embedding_cache"
    cache_dir.mkdir(parents=True, exist_ok=True)
    
    train_emb_file = cache_dir / "train_embeddings.npy"
    val_emb_file = cache_dir / "val_embeddings.npy"
    test_in_emb_file = cache_dir / "test_in_embeddings.npy"
    test_cross_emb_file = cache_dir / "test_cross_embeddings.npy"

    if train_emb_file.exists():
        logger.info("Loading cached training embeddings...")
        X_train_emb = np.load(train_emb_file)
    else:
        X_train_emb = embedder.encode(train_texts)
        np.save(train_emb_file, X_train_emb)

    if val_emb_file.exists():
        X_val_emb = np.load(val_emb_file)
    else:
        X_val_emb = embedder.encode(val_texts)
        np.save(val_emb_file, X_val_emb)

    if test_in_emb_file.exists():
        X_test_in_emb = np.load(test_in_emb_file)
    else:
        X_test_in_emb = embedder.encode(test_in_texts)
        np.save(test_in_emb_file, X_test_in_emb)

    if test_cross_emb_file.exists():
        X_test_cross_emb = np.load(test_cross_emb_file)
    else:
        X_test_cross_emb = embedder.encode(test_cross_texts)
        np.save(test_cross_emb_file, X_test_cross_emb)

    logger.info(f"Embeddings shape: {X_train_emb.shape} (dim={X_train_emb.shape[1]})")

    # Benchmark: Evaluate LogisticRegression vs MLPClassifier on Transformer Embeddings
    logger.info("Benchmarking classifiers on Transformer embeddings...")
    
    # 1. Logistic Regression (L2 regularized)
    clf_lr = LogisticRegression(C=1.0, max_iter=1000, random_state=RANDOM_STATE, class_weight="balanced")
    clf_lr.fit(X_train_emb, y_train_bin)
    val_probs_lr = clf_lr.predict_proba(X_val_emb)[:, 1]
    val_auc_lr = roc_auc_score(y_val_bin, val_probs_lr)
    val_f1_lr = f1_score(y_val_bin, (val_probs_lr >= 0.5).astype(int))

    # 2. MLP Classifier (1-hidden layer 64 neurons)
    clf_mlp = MLPClassifier(hidden_layer_sizes=(64,), max_iter=200, random_state=RANDOM_STATE, early_stopping=True)
    clf_mlp.fit(X_train_emb, y_train_bin)
    val_probs_mlp = clf_mlp.predict_proba(X_val_emb)[:, 1]
    val_auc_mlp = roc_auc_score(y_val_bin, val_probs_mlp)
    val_f1_mlp = f1_score(y_val_bin, (val_probs_mlp >= 0.5).astype(int))

    logger.info(f"LR Val ROC-AUC: {val_auc_lr:.4f}, F1: {val_f1_lr:.4f}")
    logger.info(f"MLP Val ROC-AUC: {val_auc_mlp:.4f}, F1: {val_f1_mlp:.4f}")

    # Choose top performer
    best_bin_model = clf_lr if val_auc_lr >= val_auc_mlp else clf_mlp

    # Fit 3-Class text classifier for hierarchical / 3-way breakdown (Ham, Spam, Phishing)
    clf_3class = LogisticRegression(C=1.0, max_iter=1000, random_state=RANDOM_STATE, class_weight="balanced")
    clf_3class.fit(X_train_emb, y_train_3)

    # Evaluate on In-Dist and Cross-Dataset
    test_in_probs = best_bin_model.predict_proba(X_test_in_emb)[:, 1]
    test_cross_probs = best_bin_model.predict_proba(X_test_cross_emb)[:, 1]

    metrics = {
        "transformer_model": TRANSFORMER_MODEL_NAME,
        "embedding_dim": int(X_train_emb.shape[1]),
        "best_classifier": type(best_bin_model).__name__,
        "val_roc_auc": round(float(roc_auc_score(y_val_bin, val_probs_lr)), 4),
        "test_in_roc_auc": round(float(roc_auc_score(y_test_in_bin, test_in_probs)), 4),
        "test_in_pr_auc": round(float(average_precision_score(y_test_in_bin, test_in_probs)), 4),
        "test_cross_roc_auc": round(float(roc_auc_score(y_test_cross_bin, test_cross_probs)), 4),
        "test_cross_pr_auc": round(float(average_precision_score(y_test_cross_bin, test_cross_probs)), 4),
    }

    logger.info(f"Text Model Test In-Dist ROC-AUC: {metrics['test_in_roc_auc']}, PR-AUC: {metrics['test_in_pr_auc']}")
    logger.info(f"Text Model Test Cross-Dataset ROC-AUC: {metrics['test_cross_roc_auc']}, PR-AUC: {metrics['test_cross_pr_auc']}")

    # Save trained text model bundle
    text_model_bundle = {
        "transformer_name": TRANSFORMER_MODEL_NAME,
        "binary_classifier": best_bin_model,
        "multi_classifier": clf_3class,
        "metrics": metrics
    }
    
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(text_model_bundle, MODEL_DIR / TEXT_MODEL_FILE)
    with open(ARTIFACTS_DIR / "text_model_metrics.json", "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)

    logger.info(f"Text Model successfully saved to {MODEL_DIR / TEXT_MODEL_FILE}")


if __name__ == "__main__":
    train_text_model()
