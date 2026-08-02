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

    GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")

    GEMINI_TEMPERATURE = float(os.getenv("TEMPERATURE", "0.2"))

    GEMINI_MAX_OUTPUT_TOKENS = int(os.getenv("MAX_OUTPUT_TOKENS", "8192"))

    GEMINI_TIMEOUT = int(os.getenv("TIMEOUT", "60"))
