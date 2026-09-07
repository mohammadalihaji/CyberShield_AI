import os
from pathlib import Path

# Paths
BASE_DIR = Path(__file__).resolve().parent.parent
DATASET_DIR = BASE_DIR / "data" / "compPhish_v4"
MODEL_DIR = BASE_DIR / "models" / "website_security"
ARTIFACTS_DIR = BASE_DIR / "ml" / "artifacts"

# Ensure critical directories exist
DATASET_DIR.mkdir(parents=True, exist_ok=True)
MODEL_DIR.mkdir(parents=True, exist_ok=True)
ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)

# Safe Fetcher Limits (SSRF and DoS Protection)
REQUEST_TIMEOUT = 8  # seconds
MAX_REDIRECTS = 5
MAX_HTML_SIZE = 10 * 1024 * 1024  # 10 MB limit
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 CyberShield/1.0"
ALLOWED_SCHEMES = ("http", "https")

# Disallowed Hosts & SSRF Blocklist
BLOCKED_HOSTNAMES = {
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "[::1]",
    "ip6-localhost",
    "ip6-loopback",
    "instance-data",
    "metadata.google.internal",
}

# Cloud Metadata IP addresses
METADATA_IPS = {
    "169.254.169.254",  # AWS, OpenStack, Azure, GCP
    "fd00:ec2::254",     # AWS IPv6 metadata
    "100.100.100.200",   # Alibaba Cloud metadata
}

# Risk Level Classification Thresholds
# Note: Calibrated probability P(phishing) is mapped to these bands.
RISK_THRESHOLDS = {
    "LOW": 0.20,
    "MEDIUM": 0.50,
    "HIGH": 0.75,
    "CRITICAL": 1.00
}

# Model and Training Parameters
MODEL_VERSION = "CyberShield Website Security Model v1"
RANDOM_STATE = 42
N_ESTIMATORS = 200
CALIBRATION_METHOD = "isotonic"  # or 'sigmoid'

# Feature Artifact Filenames
URL_MODEL_FILE = "url_model.joblib"
PAGE_MODEL_FILE = "page_model.joblib"
ENSEMBLE_MODEL_FILE = "ensemble_model.joblib"
CALIBRATOR_FILE = "calibrator.joblib"
FEATURE_SCHEMA_FILE = "feature_schema.json"
MODEL_METADATA_FILE = "model_metadata.json"
TRAINING_METRICS_FILE = "training_metrics.json"
