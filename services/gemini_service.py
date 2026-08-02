"""
Central Gemini AI Service for CyberShield AI.

This is the single reusable AI service that replaces all rule-based detection.
No API route calls Gemini directly — every route uses this service.

Flow:
    Build Prompt  →  Gemini API  →  Parse JSON  →  XAI Format  →  Return Response

Public methods:
    analyze_website(url)
    analyze_email(sender, body, headers=None)
    analyze_image(image_path)
    analyze_password(password)
    chat(message, history=None)
    get_security_advice(profile)
"""

import os
import re
import time
import json
import logging
from typing import Any, Callable, Dict, List, Optional

from google import genai
from google.genai import types
from PIL import Image

from config import Config
from utils.logger import get_logger
from services import prompt_manager
from services import xai_formatter
from services.response_parser import parse_and_validate, error_response, ResponseParseError

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Gemini Client Initialization
# ---------------------------------------------------------------------------

class GeminiClient:
    """
    Wraps the Google Gemini SDK (google-genai) with centralized configuration,
    error handling, and logging. All Gemini calls go through this class.
    """

    def __init__(self) -> None:
        self.api_key: str = Config.GEMINI_API_KEY
        self.model_name: str = Config.GEMINI_MODEL
        self.temperature: float = Config.GEMINI_TEMPERATURE
        self.max_output_tokens: int = Config.GEMINI_MAX_OUTPUT_TOKENS
        self.timeout: int = Config.GEMINI_TIMEOUT
        self._configured: bool = False
        self._client: Optional[genai.Client] = None
        self._configure()

    def _configure(self) -> None:
        """Configures the Gemini SDK with the API key and instantiates the client."""
        if not self.api_key:
            logger.warning("GEMINI_API_KEY is not set. Gemini features will return error responses.")
            return

        try:
            self._client = genai.Client(api_key=self.api_key)
            self._configured = True
            logger.info("Gemini AI client initialized with model '%s'.", self.model_name)
        except Exception as exc:
            logger.error("Failed to configure Gemini client: %s", exc)
            self._configured = False

    def _json_config(self) -> types.GenerateContentConfig:
        """Returns a GenerateContentConfig that forces JSON output."""
        return types.GenerateContentConfig(
            temperature=self.temperature,
            max_output_tokens=self.max_output_tokens,
            response_mime_type="application/json",
        )

    def _text_config(self) -> types.GenerateContentConfig:
        """Returns a GenerateContentConfig for plain-text (markdown) output."""
        return types.GenerateContentConfig(
            temperature=self.temperature,
            max_output_tokens=self.max_output_tokens,
        )

    def _log_request(self, analysis_type: str, prompt: str) -> None:
        """Logs a Gemini request (without the API key)."""
        logger.info(
            "Gemini request | type=%s | model=%s | prompt_length=%d chars",
            analysis_type,
            self.model_name,
            len(prompt),
        )

    def _log_response(self, analysis_type: str, duration: float, success: bool) -> None:
        """Logs a Gemini response outcome."""
        status = "SUCCESS" if success else "FAILURE"
        logger.info(
            "Gemini response | type=%s | status=%s | response_time=%.2fs",
            analysis_type,
            status,
            duration,
        )

    def _extract_text(self, response) -> str:
        """
        Safely extracts text from a Gemini response, handling safety blocks
        and empty candidates gracefully.

        Args:
            response: The raw Gemini response object.

        Returns:
            The text content of the response.

        Raises:
            RuntimeError: If the response is blocked or empty.
        """
        if response is None:
            raise RuntimeError("Gemini returned a None response.")

        # Try the .text attribute first (most common path).
        try:
            text = response.text
            if text:
                return text
        except Exception:
            pass

        # If .text failed, inspect candidates and safety ratings.
        try:
            candidates = getattr(response, "candidates", None)
            if candidates:
                candidate = candidates[0]
                # Check for safety block.
                finish_reason = getattr(candidate, "finish_reason", None)
                if finish_reason and str(finish_reason).lower() in ("safety", "reciprocity", "other"):
                    safety = getattr(candidate, "safety_ratings", None)
                    logger.warning("Gemini response blocked by safety filters: %s", safety)
                    raise RuntimeError("Gemini response was blocked by safety filters.")

                # Try to extract text from content parts.
                content = getattr(candidate, "content", None)
                if content:
                    parts = getattr(content, "parts", None)
                    if parts:
                        for part in parts:
                            part_text = getattr(part, "text", None)
                            if part_text:
                                return part_text
        except RuntimeError:
            raise
        except Exception as exc:
            logger.warning("Error inspecting Gemini candidates: %s", exc)

        # Last resort: try prompt_feedback for block reason.
        try:
            feedback = getattr(response, "prompt_feedback", None)
            if feedback:
                block_reason = getattr(feedback, "block_reason", None)
                if block_reason:
                    logger.warning("Gemini prompt blocked: %s", block_reason)
                    raise RuntimeError(f"Gemini prompt was blocked: {block_reason}")
        except RuntimeError:
            raise
        except Exception:
            pass

        raise RuntimeError("Gemini returned an empty response with no extractable text.")

    # ------------------------------------------------------------------
    # JSON cleaning & retry helpers
    # ------------------------------------------------------------------

    # Maximum number of retry attempts for failed Gemini requests.
    MAX_RETRIES: int = 3
    # Base delay (seconds) between retries; doubled each attempt.
    RETRY_BASE_DELAY: float = 1.0

    def _clean_json_response(self, text: str) -> str:
        """
        Removes markdown code fences and surrounding prose from a Gemini
        JSON response.

        Handles patterns such as:
            ```json
            { ... }
            ```
        as well as leading/trailing non-JSON text. This is a first-pass
        cleanup before the response parser applies deeper repair strategies.

        Args:
            text: The raw model response text.

        Returns:
            A cleaned string with markdown fences removed.
        """
        if not text:
            return ""

        # Remove markdown code fences if present.
        fence_pattern = re.compile(
            r"```(?:json)?\s*(.*?)\s*```",
            re.DOTALL | re.IGNORECASE,
        )
        matches = fence_pattern.findall(text)
        if matches:
            # Use the largest fenced block (most likely the JSON payload).
            text = max(matches, key=len).strip()

        # Strip any residual standalone fence markers.
        text = text.replace("```json", "").replace("```", "").strip()

        return text

    def _call_with_retry(
        self,
        operation: Callable,
        analysis_type: str,
        max_retries: Optional[int] = None,
    ) -> str:
        """
        Executes a Gemini API call with automatic retry on failure.

        Retries up to MAX_RETRIES (default 3) times with exponential
        backoff. Logs each attempt and the final outcome.

        Args:
            operation: A callable that performs the actual API call and
                returns the raw response text.
            analysis_type: Label for logging (e.g. "website").
            max_retries: Optional override for the retry count.

        Returns:
            The raw text response from Gemini (cleaned of markdown fences).

        Raises:
            RuntimeError: If all retry attempts fail.
        """
        attempts = max_retries if max_retries is not None else self.MAX_RETRIES
        last_exc: Optional[Exception] = None

        for attempt in range(1, attempts + 1):
            try:
                start_time = time.time()
                raw_text = operation()
                duration = time.time() - start_time
                self._log_response(analysis_type, duration, success=True)

                if raw_text:
                    cleaned = self._clean_json_response(raw_text)
                    logger.debug(
                        "Gemini raw response [%s] (attempt %d/%d): %s",
                        analysis_type,
                        attempt,
                        attempts,
                        cleaned[:300] if cleaned else "<empty>",
                    )
                    return cleaned
                # Empty but no exception — treat as success with empty payload.
                logger.warning(
                    "Gemini returned empty text [%s] (attempt %d/%d).",
                    analysis_type,
                    attempt,
                    attempts,
                )
                return ""

            except Exception as exc:
                last_exc = exc
                duration = 0.0
                self._log_response(analysis_type, duration, success=False)
                logger.error(
                    "Gemini call failed [%s] (attempt %d/%d): %s",
                    analysis_type,
                    attempt,
                    attempts,
                    exc,
                )

                if attempt < attempts:
                    delay = self.RETRY_BASE_DELAY * (2 ** (attempt - 1))
                    logger.info(
                        "Retrying Gemini call [%s] in %.1fs (attempt %d/%d)...",
                        analysis_type,
                        delay,
                        attempt + 1,
                        attempts,
                    )
                    time.sleep(delay)

        # All retries exhausted.
        logger.error(
            "Gemini call exhausted all %d retries [%s].",
            attempts,
            analysis_type,
        )
        raise RuntimeError(
            f"Gemini request failed after {attempts} attempts [{analysis_type}]: {last_exc}"
        ) from last_exc

    # ------------------------------------------------------------------
    # Public generation methods (with retry)
    # ------------------------------------------------------------------

    def generate_text(self, prompt: str, analysis_type: str) -> str:
        """
        Sends a text prompt to Gemini and returns the raw text response.

        Includes automatic retry (up to 3 attempts) and JSON markdown
        fence cleaning.

        Args:
            prompt: The fully-formed prompt string.
            analysis_type: Label for logging (e.g. "website").

        Returns:
            The raw text response from Gemini (markdown fences removed).

        Raises:
            RuntimeError: If Gemini is not configured or all retries fail.
        """
        if not self._configured or self._client is None:
            raise RuntimeError("Gemini client is not configured. Check GEMINI_API_KEY.")

        self._log_request(analysis_type, prompt)

        def _operation() -> str:
            response = self._client.models.generate_content(
                model=self.model_name,
                contents=prompt,
                config=self._json_config(),
            )
            return self._extract_text(response)

        return self._call_with_retry(_operation, analysis_type)

    def generate_with_image(self, prompt: str, image_path: str, analysis_type: str) -> str:
        """
        Sends a text prompt + image to Gemini Vision and returns the raw
        text response.

        Includes automatic retry (up to 3 attempts) and JSON markdown
        fence cleaning.

        Args:
            prompt: The fully-formed prompt string.
            image_path: Path to the image file on disk.
            analysis_type: Label for logging (e.g. "image").

        Returns:
            The raw text response from Gemini (markdown fences removed).

        Raises:
            RuntimeError: If Gemini is not configured or all retries fail.
        """
        if not self._configured or self._client is None:
            raise RuntimeError("Gemini vision client is not configured. Check GEMINI_API_KEY.")

        self._log_request(analysis_type, prompt)

        def _operation() -> str:
            pil_image = Image.open(image_path)
            response = self._client.models.generate_content(
                model=self.model_name,
                contents=[prompt, pil_image],
                config=self._json_config(),
            )
            return self._extract_text(response)

        return self._call_with_retry(_operation, analysis_type)

    def generate_chat(self, prompt: str, analysis_type: str) -> str:
        """
        Sends a chat prompt to Gemini and returns the raw markdown text response.

        Includes automatic retry (up to 3 attempts).

        Args:
            prompt: The fully-formed prompt string.
            analysis_type: Label for logging (always "chat").

        Returns:
            The raw text response from Gemini.

        Raises:
            RuntimeError: If Gemini is not configured or all retries fail.
        """
        if not self._configured or self._client is None:
            raise RuntimeError("Gemini chat client is not configured. Check GEMINI_API_KEY.")

        self._log_request(analysis_type, prompt)

        def _operation() -> str:
            response = self._client.models.generate_content(
                model=self.model_name,
                contents=prompt,
                config=self._text_config(),
            )
            return self._extract_text(response)

        return self._call_with_retry(_operation, analysis_type)


# ---------------------------------------------------------------------------
# Singleton client instance
# ---------------------------------------------------------------------------

_client: Optional[GeminiClient] = None


def _get_client() -> GeminiClient:
    """Returns the singleton GeminiClient, initializing on first use."""
    global _client
    if _client is None:
        _client = GeminiClient()
    return _client


# ---------------------------------------------------------------------------
# Public Service Methods
# ---------------------------------------------------------------------------

def analyze_website(url: str) -> Dict[str, Any]:
    """
    Analyzes a URL for phishing and malicious indicators using Gemini AI.

    Args:
        url: The target URL to evaluate.

    Returns:
        A schema-validated dictionary with risk assessment and XAI markdown report.
    """
    if not url or not url.strip():
        return error_response("website", "URL parameter is empty.")

    try:
        prompt = prompt_manager.website_prompt(url)
        raw = _get_client().generate_text(prompt, "website")
        result = parse_and_validate(raw)
        # Preserve Gemini's XAI report; only auto-format when Gemini omits it.
        if not result.get("explanation_markdown"):
            result["explanation_markdown"] = xai_formatter.format_report(result, "website")
        return result
    except ResponseParseError as exc:
        logger.error("Website analysis parse error: %s", exc)
        return error_response("website", str(exc))
    except Exception as exc:
        logger.error("Website analysis error: %s", exc)
        return error_response("website", str(exc))


def analyze_email(sender: str, body: str, headers: Optional[str] = None) -> Dict[str, Any]:
    """
    Analyzes an email for phishing, spoofing, and BEC indicators using Gemini AI.

    Args:
        sender: The sender email address.
        body: The email body text.
        headers: Optional raw email headers.

    Returns:
        A schema-validated dictionary with risk assessment and XAI markdown report.
    """
    if not sender or not body:
        return error_response("email", "Sender and email body are required.")

    try:
        prompt = prompt_manager.email_prompt(sender, body, headers)
        raw = _get_client().generate_text(prompt, "email")
        result = parse_and_validate(raw)
        # Preserve Gemini's XAI report; only auto-format when Gemini omits it.
        if not result.get("explanation_markdown"):
            result["explanation_markdown"] = xai_formatter.format_report(result, "email")
        return result
    except ResponseParseError as exc:
        logger.error("Email analysis parse error: %s", exc)
        return error_response("email", str(exc))
    except Exception as exc:
        logger.error("Email analysis error: %s", exc)
        return error_response("email", str(exc))


def analyze_image(image_path: str) -> Dict[str, Any]:
    """
    Analyzes an uploaded image for AI-generation, manipulation, and authenticity
    using Gemini Vision.

    Pre-processes the image with the forensic engine to extract objective
    forensic indicators (ELA, noise, lighting, metadata, etc.) before sending
    to Gemini. Gemini explains the evidence rather than inventing it.

    Args:
        image_path: Path to the image file on disk.

    Returns:
        A schema-validated dictionary with forensic assessment and XAI markdown report.
    """
    if not image_path or not os.path.exists(image_path):
        return error_response("image", "Image file not found.")

    try:
        # Run local forensic pre-processing.
        from services.image_forensics import analyze_image_forensics
        forensic_data = analyze_image_forensics(image_path)
        logger.info("Image forensics extracted: %d indicators", len(forensic_data))

        filename = os.path.basename(image_path)
        prompt = prompt_manager.image_prompt(filename, forensic_data)
        raw = _get_client().generate_with_image(prompt, image_path, "image")
        result = parse_and_validate(raw)

        # Merge forensic data into the result so the XAI formatter can display it.
        for key, value in forensic_data.items():
            if key not in result or not result[key]:
                result[key] = value

        # Preserve Gemini's XAI report; only auto-format when Gemini omits it.
        if not result.get("explanation_markdown"):
            result["explanation_markdown"] = xai_formatter.format_report(result, "image")
        return result
    except ResponseParseError as exc:
        logger.error("Image analysis parse error: %s", exc)
        return error_response("image", str(exc))
    except Exception as exc:
        logger.error("Image analysis error: %s", exc)
        return error_response("image", str(exc))


def _compute_password_metadata(password: str) -> Dict[str, Any]:
    """
    Computes anonymized password metrics locally so the raw password is never
    sent to Gemini.

    Analyzes length, character-type coverage, entropy, common word/keyboard-walk
    patterns, and dictionary risk.

    Args:
        password: The plaintext password to analyze locally.

    Returns:
        A dictionary of anonymized metrics suitable for the Gemini prompt.
    """
    import math

    length = len(password)
    has_upper = any(ch.isupper() for ch in password)
    has_lower = any(ch.islower() for ch in password)
    has_digit = any(ch.isdigit() for ch in password)
    has_special = any(not ch.isalnum() for ch in password)

    # Character set size for entropy estimation.
    charset_size = 0
    if has_lower:
        charset_size += 26
    if has_upper:
        charset_size += 26
    if has_digit:
        charset_size += 10
    if has_special:
        charset_size += 32

    entropy = round(length * math.log2(max(charset_size, 2)), 1) if length else 0

    # Risk classification.
    common_list = ["password", "123456", "qwerty", "p@ssword", "welcome", "letmein",
                   "admin", "iloveyou", "abc123", "111111", "000000", "password1"]
    is_common_word = any(word in password.lower() for word in common_list)

    keyboard_walks = ["qwerty", "asdfgh", "zxcvbn", "qazwsx", "123456", "654321", "qwertyuiop"]
    keyboard_walk = any(walk in password.lower() for walk in keyboard_walks)

    common_patterns = []
    if is_common_word:
        common_patterns.append("Common word detected")
    if keyboard_walk:
        common_patterns.append("Keyboard walk detected")
    if re.search(r"(.)\1{2,}", password):
        common_patterns.append("Repeated characters")
    if re.search(r"\d{3,}", password):
        common_patterns.append("Sequential / repeated digits")

    if length < 8 or is_common_word:
        risk = "Weak"
    elif length < 12 or entropy < 60:
        risk = "Medium"
    else:
        risk = "Strong"

    return {
        "length": length,
        "has_uppercase": has_upper,
        "has_lowercase": has_lower,
        "has_digit": has_digit,
        "has_special": has_special,
        "entropy": entropy,
        "risk": risk,
        "pwned_count": 0,
        "common_patterns": common_patterns,
        "is_common_word": is_common_word,
        "keyboard_walk": keyboard_walk,
    }


def analyze_password(password: str) -> Dict[str, Any]:
    """
    Analyzes a password for strength, entropy, and breach risk using Gemini AI.

    Only anonymized password metadata is sent to Gemini — the raw password
    never leaves the server.

    Args:
        password: The plaintext password to evaluate.

    Returns:
        A schema-validated dictionary with strength assessment and XAI markdown report.
    """
    if not password:
        return error_response("password", "Password input is empty.")

    try:
        metadata = _compute_password_metadata(password)
        prompt = prompt_manager.password_prompt(metadata)
        raw = _get_client().generate_text(prompt, "password")
        result = parse_and_validate(raw)

        # Merge locally-computed anonymized metrics so the response is always
        # complete and consistent even if Gemini omits a field.
        for key, value in metadata.items():
            if key not in result or result[key] in (None, "", 0, False):
                result[key] = value

        # Preserve Gemini's XAI report; only auto-format when Gemini omits it.
        if not result.get("explanation_markdown"):
            result["explanation_markdown"] = xai_formatter.format_report(result, "password")
        return result
    except ResponseParseError as exc:
        logger.error("Password analysis parse error: %s", exc)
        return error_response("password", str(exc))
    except Exception as exc:
        logger.error("Password analysis error: %s", exc)
        return error_response("password", str(exc))


def get_security_advice(profile: Dict[str, Any]) -> Dict[str, Any]:
    """
    Processes a personal security posture questionnaire using Gemini AI.

    Args:
        profile: A dictionary of questionnaire responses.

    Returns:
        A schema-validated dictionary with overall score and XAI markdown report.
    """
    if not profile:
        return error_response("advisor", "Security profile is empty.")

    try:
        prompt = prompt_manager.advisor_prompt(profile)
        raw = _get_client().generate_text(prompt, "advisor")
        result = parse_and_validate(raw)
        # Preserve Gemini's advisor report; only auto-format when Gemini omits it.
        if not result.get("general_advisor_markdown"):
            result["general_advisor_markdown"] = xai_formatter.format_report(result, "advisor")
        return result
    except ResponseParseError as exc:
        logger.error("Advisor analysis parse error: %s", exc)
        return error_response("advisor", str(exc))
    except Exception as exc:
        logger.error("Advisor analysis error: %s", exc)
        return error_response("advisor", str(exc))


def chat(message: str, history: Optional[List[Dict[str, str]]] = None) -> str:
    """
    Processes a cybersecurity assistant chat message using Gemini AI.

    Args:
        message: The latest user message.
        history: Optional list of prior conversation turns.

    Returns:
        The assistant's reply as a markdown-formatted string.
    """
    if not message or not message.strip():
        return "I didn't receive a message. Please ask a cybersecurity question and I'll help you."

    try:
        prompt = prompt_manager.chat_prompt(message, history)
        raw = _get_client().generate_chat(prompt, "chat")
        return raw.strip()
    except Exception as exc:
        logger.error("Chat error: %s", exc)
        return (
            "⚠️ I'm unable to process your request right now due to a connection issue "
            "with the AI engine. Please try again shortly."
        )


# ---------------------------------------------------------------------------
# Backward-compatible aliases
# ---------------------------------------------------------------------------

def process_chat_message(message: str, history: Optional[List[Dict[str, str]]] = None) -> str:
    """Backward-compatible alias for chat()."""
    return chat(message, history)


def get_password_advice(password: str) -> Dict[str, Any]:
    """Backward-compatible wrapper that delegates to analyze_password()."""
    return analyze_password(password)