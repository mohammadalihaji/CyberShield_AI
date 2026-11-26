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

    # gemini-2.5-flash returns 404 for new API keys. Keep accepting the old
    # name from Render env vars and send gemini-3.8-flash instead.
    _GEMINI_MODEL_DEFAULT = "gemini-3.8-flash"
    _RETIRED_GEMINI_MODELS = {
        "gemini-2.5-flash",
        "models/gemini-2.5-flash",
    }
    _requested_model = (os.getenv("GEMINI_MODEL") or _GEMINI_MODEL_DEFAULT).strip()
    GEMINI_MODEL = (
        _GEMINI_MODEL_DEFAULT
        if _requested_model in _RETIRED_GEMINI_MODELS
        else _requested_model.removeprefix("models/") or _GEMINI_MODEL_DEFAULT
    )

    GEMINI_TEMPERATURE = float(os.getenv("TEMPERATURE", "0.2"))

    GEMINI_MAX_OUTPUT_TOKENS = int(os.getenv("MAX_OUTPUT_TOKENS", "8192"))

    GEMINI_TIMEOUT = int(os.getenv("TIMEOUT", "60"))
