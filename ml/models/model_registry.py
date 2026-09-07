import os
import json
import logging
from pathlib import Path
from typing import Optional, Dict, Any, Tuple
import joblib

from ml.config import (
    MODEL_DIR,
    URL_MODEL_FILE,
    PAGE_MODEL_FILE,
    ENSEMBLE_MODEL_FILE,
    CALIBRATOR_FILE,
    FEATURE_SCHEMA_FILE,
    MODEL_METADATA_FILE,
    MODEL_VERSION
)

logger = logging.getLogger(__name__)


class ModelRegistry:
    """
    Manages persistence, metadata serialization, and loading of trained website security models.
    """

    def __init__(self, model_dir: Path = MODEL_DIR):
        self.model_dir = Path(model_dir)
        self.model_dir.mkdir(parents=True, exist_ok=True)

    def is_model_ready(self) -> bool:
        """
        Returns True ONLY if trained model artifact files exist on disk.
        Does NOT pretend or use fake/placeholder models.
        """
        required_files = [
            self.model_dir / URL_MODEL_FILE,
            self.model_dir / FEATURE_SCHEMA_FILE
        ]
        return all(f.exists() for f in required_files)

    def save_models(
        self,
        url_model: Any,
        page_model: Optional[Any],
        ensemble_model: Optional[Any],
        calibrator: Optional[Any],
        schema_metadata: Dict[str, Any],
        training_metrics: Dict[str, Any],
        dataset_info: Dict[str, Any]
    ) -> Dict[str, str]:
        """
        Saves all trained models, calibrator, schema, and metadata to the model directory.
        """
        saved_paths = {}

        # Save URL model
        url_path = self.model_dir / URL_MODEL_FILE
        joblib.dump(url_model, url_path)
        saved_paths["url_model"] = str(url_path)

        # Save Page model if available
        if page_model is not None:
            page_path = self.model_dir / PAGE_MODEL_FILE
            joblib.dump(page_model, page_path)
            saved_paths["page_model"] = str(page_path)

        # Save Ensemble model if available
        if ensemble_model is not None:
            ens_path = self.model_dir / ENSEMBLE_MODEL_FILE
            joblib.dump(ensemble_model, ens_path)
            saved_paths["ensemble_model"] = str(ens_path)

        # Save Calibrator if available
        if calibrator is not None:
            cal_path = self.model_dir / CALIBRATOR_FILE
            joblib.dump(calibrator, cal_path)
            saved_paths["calibrator"] = str(cal_path)

        # Save Feature Schema
        schema_path = self.model_dir / FEATURE_SCHEMA_FILE
        with open(schema_path, "w", encoding="utf-8") as f:
            json.dump(schema_metadata, f, indent=2)
        saved_paths["feature_schema"] = str(schema_path)

        # Save Metadata
        metadata = {
            "model_version": MODEL_VERSION,
            "training_metrics": training_metrics,
            "dataset_info": dataset_info,
            "schema_summary": {
                "url_feature_count": schema_metadata.get("url_feature_count", 0),
                "page_feature_count": schema_metadata.get("page_feature_count", 0),
            }
        }
        meta_path = self.model_dir / MODEL_METADATA_FILE
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(metadata, f, indent=2)
        saved_paths["metadata"] = str(meta_path)

        logger.info(f"Model artifacts successfully saved to {self.model_dir}")
        return saved_paths

    def load_models(self) -> Dict[str, Any]:
        """
        Loads all available model artifacts from disk.
        Returns dict containing models or None if not trained yet.
        """
        if not self.is_model_ready():
            return {
                "is_ready": False,
                "url_model": None,
                "page_model": None,
                "ensemble_model": None,
                "calibrator": None,
                "feature_schema": None,
                "metadata": None
            }

        url_model = joblib.load(self.model_dir / URL_MODEL_FILE)
        
        page_model = None
        if (self.model_dir / PAGE_MODEL_FILE).exists():
            page_model = joblib.load(self.model_dir / PAGE_MODEL_FILE)

        ensemble_model = None
        if (self.model_dir / ENSEMBLE_MODEL_FILE).exists():
            ensemble_model = joblib.load(self.model_dir / ENSEMBLE_MODEL_FILE)

        calibrator = None
        if (self.model_dir / CALIBRATOR_FILE).exists():
            calibrator = joblib.load(self.model_dir / CALIBRATOR_FILE)

        feature_schema = None
        if (self.model_dir / FEATURE_SCHEMA_FILE).exists():
            with open(self.model_dir / FEATURE_SCHEMA_FILE, "r", encoding="utf-8") as f:
                feature_schema = json.load(f)

        metadata = None
        if (self.model_dir / MODEL_METADATA_FILE).exists():
            with open(self.model_dir / MODEL_METADATA_FILE, "r", encoding="utf-8") as f:
                metadata = json.load(f)

        return {
            "is_ready": True,
            "url_model": url_model,
            "page_model": page_model,
            "ensemble_model": ensemble_model,
            "calibrator": calibrator,
            "feature_schema": feature_schema,
            "metadata": metadata
        }
