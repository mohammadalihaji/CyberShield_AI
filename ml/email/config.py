import os
from pathlib import Path

# Base directories
BASE_DIR = Path(__file__).resolve().parent.parent.parent
DATA_DIR = BASE_DIR / "data" / "email"
RAW_DATA_DIR = DATA_DIR / "raw"
PROCESSED_DATA_DIR = DATA_DIR / "processed"
MODEL_DIR = BASE_DIR / "models" / "email"
ARTIFACTS_DIR = BASE_DIR / "ml" / "email" / "artifacts"
DOCS_DIR = BASE_DIR / "docs"

# Ensure runtime directories exist
PROCESSED_DATA_DIR.mkdir(parents=True, exist_ok=True)
MODEL_DIR.mkdir(parents=True, exist_ok=True)
ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)

# Safe Parsing Limits (MIME & DoS protection)
MAX_EMAIL_SIZE_BYTES = 10 * 1024 * 1024  # 10 MB limit for raw EML
MAX_BODY_TEXT_LENGTH = 100_000          # 100k characters
MAX_URLS_TO_ANALYZE = 50                # Up to 50 URLs extracted per message
MAX_ATTACHMENTS = 25                    # Up to 25 attachments inspected metadata-only

# High-risk extensions for static inspection
EXECUTABLE_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".js", ".vbs", ".ps1", ".hta", ".wsf",
    ".cpl", ".msi", ".jar", ".com", ".pif", ".gadget"
}

MACRO_EXTENSIONS = {
    ".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".potm", ".xla", ".xlam"
}

ARCHIVE_EXTENSIONS = {
    ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".iso", ".img", ".cab"
}

# Suspicious Subject / Body Keywords for Heuristics
SUSPICIOUS_EMAIL_KEYWORDS = [
    "verify", "urgent", "immediate", "suspended", "account", "unauthorized",
    "password", "security alert", "billing", "invoice", "confirm", "action required",
    "banking", "wire transfer", "cryptocurrency", "wallet", "irs", "tax refund",
    "payment overdue", "login required", "click here", "debit", "credit card",
    "payroll", "direct deposit", "lottery", "winner", "inheritance", "nigerian"
]

# Model Configuration
MODEL_VERSION = "CyberShield-Email-Security-v1"
FEATURE_SCHEMA_VERSION = "1.0.0"
RANDOM_STATE = 42
N_OOF_FOLDS = 5
TRANSFORMER_MODEL_NAME = "all-MiniLM-L6-v2"

# File names for trained artifacts
TEXT_MODEL_FILE = "email_text_model.joblib"
STRUCTURED_MODEL_FILE = "email_structured_model.joblib"
META_MODEL_FILE = "email_meta_model.joblib"
CALIBRATOR_FILE = "email_calibrator.joblib"
METADATA_FILE = "metadata.json"
FEATURE_SCHEMA_FILE = "feature_schema.json"
CALIBRATION_CURVE_FILE = "calibration_curve.json"

# Decision Thresholds (Calibrated Probability Bands)
# 0.00 - 0.35: Legitimate (Ham)
# 0.35 - 0.70: Suspicious / Uncertain
# 0.70 - 1.00: Malicious (Spam / Phishing)
DECISION_THRESHOLDS = {
    "LEGITIMATE_MAX": 0.35,
    "SUSPICIOUS_MAX": 0.70,
    "MALICIOUS_MIN": 0.70,
    "PHISHING_SUB_THRESHOLD": 0.60  # Within malicious, score threshold for Phishing vs Spam
}
