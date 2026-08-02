"""
Centralized logging configuration for CyberShield AI.

Provides a reusable logger factory that enforces consistent formatting
across the application. API keys and other secrets are never logged.
"""

import os
import logging
from logging.handlers import RotatingFileHandler

# Ensure the logs directory exists next to the project root.
_LOG_DIR = os.path.join(os.path.abspath(os.path.dirname(__file__)), "..", "logs")
os.makedirs(_LOG_DIR, exist_ok=True)

_LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

_configured = False


def _configure_root_logger() -> None:
    """Idempotently attaches console + rotating file handlers to the root logger."""
    global _configured
    if _configured:
        return

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)

    formatter = logging.Formatter(_LOG_FORMAT, datefmt=_DATE_FORMAT)

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)

    # Rotating file handler (5 MB per file, 3 backups)
    file_handler = RotatingFileHandler(
        filename=os.path.join(_LOG_DIR, "cybershield.log"),
        maxBytes=5 * 1024 * 1024,
        backupCount=3,
        encoding="utf-8",
    )
    file_handler.setFormatter(formatter)
    root_logger.addHandler(file_handler)

    _configured = True


def get_logger(name: str) -> logging.Logger:
    """
    Returns a configured logger instance.

    Args:
        name: Usually __name__ of the calling module.

    Returns:
        A logging.Logger instance with consistent formatting.
    """
    _configure_root_logger()
    return logging.getLogger(name)


# Initialize on import so every module gets a ready-to-use logger.
configure = _configure_root_logger