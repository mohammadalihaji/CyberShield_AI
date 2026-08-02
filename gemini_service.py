"""
Root-level facade for the Gemini AI service.

Re-exports the public methods from services.gemini_service so that
existing imports (e.g. `import gemini_service`) continue to work
without changing app.py or any other caller.
"""

from services.gemini_service import (
    analyze_website,
    analyze_email,
    analyze_image,
    analyze_password,
    get_security_advice,
    chat,
    process_chat_message,
    get_password_advice,
)

__all__ = [
    "analyze_website",
    "analyze_email",
    "analyze_image",
    "analyze_password",
    "get_security_advice",
    "chat",
    "process_chat_message",
    "get_password_advice",
]