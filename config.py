import os
from dotenv import load_dotenv

load_dotenv()


class Config:

    SECRET_KEY = os.getenv(
        "SECRET_KEY",
        "change-this-secret-key"
    )

    SQLALCHEMY_DATABASE_URI = os.getenv(
        "DATABASE_URL",
        "sqlite:///cybershield.db"
    )

    SQLALCHEMY_TRACK_MODIFICATIONS = False

    JWT_SECRET_KEY = os.getenv(
        "JWT_SECRET_KEY",
        "change-this-jwt-secret"
    )

    UPLOAD_FOLDER = os.getenv(
        "UPLOAD_FOLDER",
        "uploads"
    )

    MAX_CONTENT_LENGTH = 16 * 1024 * 1024

    # ===================================================================
    # Gemini AI Configuration
    # ===================================================================
    GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")

    # New free API keys cannot call gemini-2.5-flash or gemini-2.5-flash-lite.
    # Google returns 404 and names gemini-3.5-flash-lite as the replacement.
    _GEMINI_MODEL_DEFAULT = "gemini-3.5-flash-lite"
    _RETIRED_GEMINI_MODELS = {
        "",
        "gemini-2.0-flash",
        "gemini-2.5-flash",
        "gemini-2.5-flash-lite",
        "gemini-3.8-flash",
    }
    _requested_model = (os.getenv("GEMINI_MODEL") or _GEMINI_MODEL_DEFAULT).strip()
    _requested_model = _requested_model.removeprefix("models/")
    GEMINI_MODEL = (
        _GEMINI_MODEL_DEFAULT
        if _requested_model in _RETIRED_GEMINI_MODELS
        else _requested_model
    )

    GEMINI_TEMPERATURE = float(os.getenv("TEMPERATURE", "0.2"))

    GEMINI_MAX_OUTPUT_TOKENS = int(os.getenv("MAX_OUTPUT_TOKENS", "8192"))

    GEMINI_TIMEOUT = int(os.getenv("TIMEOUT", "60"))
