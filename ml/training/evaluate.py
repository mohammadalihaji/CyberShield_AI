import sys
import logging
from pathlib import Path
from ml.config import MODEL_DIR
from ml.models.model_registry import ModelRegistry

logger = logging.getLogger(__name__)


def evaluate_models():
    registry = ModelRegistry(MODEL_DIR)
    if not registry.is_model_ready():
        print("============================================================")
        print("Model evaluation skipped: No trained model artifacts found.")
        print("Models will be evaluated automatically after training.")
        print("============================================================")
        return

    models = registry.load_models()
    meta = models.get("metadata", {})
    print("============================================================")
    print("CyberShield AI Model Evaluation Summary")
    print("============================================================")
    print(f"Model Version: {meta.get('model_version', 'N/A')}")
    print(f"Training Metrics: {meta.get('training_metrics', {})}")
    print(f"Dataset Info: {meta.get('dataset_info', {})}")
    print("============================================================")


if __name__ == "__main__":
    evaluate_models()
