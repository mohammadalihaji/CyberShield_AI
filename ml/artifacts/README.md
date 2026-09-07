# CyberShield Website Security ML Artifacts

This directory stores serialized model artifacts and metadata generated from CompPhish Version 4 training:

- `url_model.joblib`: Trained URL Random Forest classifier
- `page_model.joblib`: Trained Page/HTML classifier
- `ensemble_model.joblib`: Calibrated multi-modal ensemble model
- `calibrator.joblib`: Probability calibration weights
- `feature_schema.json`: Ordered list of exact feature names and counts
- `model_metadata.json`: Model version, date, hyperparameters, and evaluation metrics
- `training_metrics.json`: Detailed validation ROC-AUC, F1, Precision, Recall

These artifacts are generated when training is executed via `python -m ml.training.train_url_model` after dataset confirmation.
