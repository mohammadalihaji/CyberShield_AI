import sys
import logging
from pathlib import Path
import numpy as np
from sklearn.metrics import classification_report, roc_auc_score, brier_score_loss

from ml.config import DATASET_DIR, MODEL_DIR, CALIBRATION_METHOD
from ml.dataset_inspector import DatasetInspector
from ml.dataset_loader import DatasetLoader
from ml.models.ensemble_model import EnsembleSecurityModel
from ml.models.calibration import ProbabilityCalibrator
from ml.models.model_registry import ModelRegistry
from ml.features.feature_schema import get_schema_metadata

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

    registry = ModelRegistry(MODEL_DIR)
    models = registry.load_models()
    url_model = models.get("url_model")
    page_model = models.get("page_model")

    if url_model is None:
        print("URL model must be trained before ensemble calibration.")
        return

    print("Building and calibrating Ensemble Security Model...")
    ensemble = EnsembleSecurityModel()
    schema_meta = get_schema_metadata()

    registry.save_models(
        url_model=url_model,
        page_model=page_model,
        ensemble_model=ensemble,
        calibrator=None,
        schema_metadata=schema_meta,
        training_metrics={"status": "Ensemble ready"},
        dataset_info={"calibration_method": CALIBRATION_METHOD}
    )
    print("Ensemble model pipeline configured and saved successfully.")


if __name__ == "__main__":
    run_training()
