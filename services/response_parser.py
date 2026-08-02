"""
JSON Response Parser for CyberShield AI.

Responsibilities:
- Remove markdown fences and stray text from Gemini responses.
- Repair common JSON issues (raw newlines in strings, trailing commas,
  truncated responses).
- Parse JSON safely with multiple fallback strategies.
- Validate the shared analysis schema.
- Raise meaningful errors on failure.
"""

import json
import re
import logging
from typing import Any, Dict, List, Optional

from utils.logger import get_logger

logger = get_logger(__name__)

# Required keys in the shared analysis schema.
REQUIRED_KEYS: List[str] = [
    "analysis_type",
    "risk_level",
    "confidence",
    "summary",
    "reasoning",
    "recommendations",
    "limitations",
]

# Optional XAI / forensic fields that may be returned by Gemini for specific
# modules. These are NOT required, but when present they are type-normalized
# so the frontend and XAI formatter receive consistent values.
OPTIONAL_XAI_FIELDS: Dict[str, Any] = {
    # Image forensics fields
    "ai_probability": 0,
    "ai_confidence": 0,
    "ela_score": 0.0,
    "noise_score": "",
    "lighting_consistency": "",
    "pixel_irregularity": "",
    "compression_analysis": "",
    "metadata_status": "",
    "organic_texture": "",
    "gan_artifacts": "",
    "fingerprints": "",
    "jpeg_artifacts": "",
    "jpeg_quality": 0,
    "resolution": "",
    "edge_density": "",
    "sharpness": "",
    "color_distribution": "",
    "texture_consistency": "",
    # Website fields
    "phishing_score": 0,
    "ssl_valid": False,
    "malware_found": False,
    "domain_age": "Unknown",
    "reputation": "Unverified",
    # Email fields
    "urgency": "Normal",
    "suspicious_links": 0,
    "spoofed_domain": False,
    "spf_check": "Not Available",
    "dkim_check": "Not Available",
    "dmarc_check": "Not Available",
    "social_engineering": "Not Assessed",
    # Password fields
    "entropy": 0,
    "pwned_count": 0,
    "has_uppercase": False,
    "has_lowercase": False,
    "has_digit": False,
    "has_special": False,
    "dictionary_risk": "Not Assessed",
    "pattern_detection": "None Detected",
    "estimated_crack_time": "N/A",
    # Advisor fields
    "overall_score": 0,
    # Shared XAI markdown report
    "explanation_markdown": "",
    "general_advisor_markdown": "",
}


class ResponseParseError(Exception):
    """Raised when a Gemini response cannot be parsed into valid JSON."""


def _strip_markdown(text: str) -> str:
    """
    Removes markdown code fences and surrounding prose from a model response.

    Handles patterns such as:
        ```json
        { ... }
        ```
    as well as leading/trailing non-JSON text.

    Args:
        text: The raw model response text.

    Returns:
        A cleaned string that should contain only JSON.
    """
    if not text:
        return ""

    # Remove markdown code fences if present.
    fence_pattern = re.compile(r"```(?:json)?\s*(.*?)\s*```", re.DOTALL | re.IGNORECASE)
    matches = fence_pattern.findall(text)
    if matches:
        # Use the largest fenced block (most likely the JSON payload).
        text = max(matches, key=len).strip()

    # If no fences, try to extract the outermost JSON object.
    if not text.strip().startswith("{"):
        obj_match = re.search(r"\{.*\}", text, re.DOTALL)
        if obj_match:
            text = obj_match.group(0).strip()

    return text.strip()


def _repair_raw_newlines_in_strings(text: str) -> str:
    """
    Escapes raw control characters that appear inside JSON string values.

    The most common issue with LLM-generated JSON is that the model places
    literal newlines, tabs, or carriage returns inside string values (e.g.
    inside a markdown explanation field).  Standard JSON requires these to
    be escaped as \\n, \\t, \\r.

    This function walks the text character-by-character, tracking whether
    we are inside a string (between unescaped double quotes) and escapes
    any control characters found there.

    Args:
        text: Raw JSON text that may contain invalid control characters.

    Returns:
        JSON text with all in-string control characters properly escaped.
    """
    result: List[str] = []
    in_string = False
    escaped = False

    for char in text:
        if escaped:
            # Previous char was a backslash — this char is literal.
            result.append(char)
            escaped = False
            continue

        if char == "\\":
            result.append(char)
            escaped = True
            continue

        if char == '"':
            in_string = not in_string
            result.append(char)
            continue

        if in_string:
            # Inside a string — escape control characters.
            if char == "\n":
                result.append("\\n")
                continue
            elif char == "\r":
                result.append("\\r")
                continue
            elif char == "\t":
                result.append("\\t")
                continue
            elif ord(char) < 32:
                # Other control characters (form feed, backspace, etc.)
                result.append(f"\\u{ord(char):04x}")
                continue

        result.append(char)

    return "".join(result)


def _remove_trailing_commas(text: str) -> str:
    """
    Removes trailing commas that appear before closing braces/brackets.

    LLMs sometimes produce JSON like:
        {"key": "value",}
    which is invalid.  This fixes it by removing the comma.

    Args:
        text: JSON text that may contain trailing commas.

    Returns:
        JSON text with trailing commas removed.
    """
    # Remove trailing commas before } or ]
    text = re.sub(r",(\s*[}\]])", r"\1", text)
    return text


def _close_truncated_json(text: str) -> str:
    """
    Attempts to repair truncated JSON by closing open strings, arrays,
    and objects.

    When the Gemini response is cut off (e.g. due to max_output_tokens),
    the JSON may end mid-string like:
        {"key": "some value without closing quote

    This function tries to close the truncated JSON so it can be parsed.

    Args:
        text: Potentially truncated JSON text.

    Returns:
        JSON text with closing brackets/quotes appended if needed.
    """
    # First, check if the text ends with a complete JSON object.
    stripped = text.rstrip()
    if stripped.endswith("}"):
        return text

    # Track string context and bracket depth.
    in_string = False
    escaped = False
    stack: List[str] = []

    for char in text:
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if char == '"':
            in_string = not in_string
            continue
        if in_string:
            continue
        if char in "{[":
            stack.append("}" if char == "{" else "]")
        elif char in "}]":
            if stack and stack[-1] == char:
                stack.pop()

    # If we're inside a string, close it.
    suffix = ""
    if in_string:
        suffix += '"'

    # Close any open brackets/braces.
    while stack:
        suffix += stack.pop()

    if suffix:
        logger.debug("Closing truncated JSON with suffix: %s", suffix)
        return text + suffix

    return text


def _repair_json(text: str) -> str:
    """
    Applies a series of repair strategies to fix common JSON issues
    produced by LLMs.

    Args:
        text: Raw JSON text that may be invalid.

    Returns:
        Repaired JSON text.
    """
    # Step 1: Escape raw control characters inside string values.
    text = _repair_raw_newlines_in_strings(text)

    # Step 2: Remove trailing commas.
    text = _remove_trailing_commas(text)

    return text


def parse_json_response(raw_text: str) -> Dict[str, Any]:
    """
    Parses a Gemini response into a validated dictionary.

    Uses multiple fallback strategies:
    1. Direct json.loads after stripping markdown.
    2. JSON repair (escape raw newlines, remove trailing commas).
    3. Truncation repair (close open strings/brackets).
    4. Regex extraction of key-value pairs (last resort).

    Args:
        raw_text: The raw text returned by the Gemini model.

    Returns:
        A dictionary containing the parsed JSON.

    Raises:
        ResponseParseError: If the text cannot be parsed or is missing
            required schema keys.
    """
    if not raw_text or not raw_text.strip():
        raise ResponseParseError("Empty response received from Gemini.")

    cleaned = _strip_markdown(raw_text)

    # Strategy 1: Direct parse.
    try:
        data = json.loads(cleaned)
        if isinstance(data, dict):
            return data
    except json.JSONDecodeError as exc:
        logger.debug("Direct JSON parse failed (strategy 1): %s", exc)

    # Strategy 2: Repair raw newlines and trailing commas, then parse.
    try:
        repaired = _repair_json(cleaned)
        data = json.loads(repaired)
        if isinstance(data, dict):
            logger.info("JSON parsed successfully after repair (strategy 2).")
            return data
    except json.JSONDecodeError as exc:
        logger.debug("Repaired JSON parse failed (strategy 2): %s", exc)

    # Strategy 3: Close truncated JSON, then parse.
    try:
        closed = _close_truncated_json(cleaned)
        closed = _repair_json(closed)
        data = json.loads(closed)
        if isinstance(data, dict):
            logger.info("JSON parsed successfully after truncation repair (strategy 3).")
            return data
    except json.JSONDecodeError as exc:
        logger.debug("Truncation-repaired JSON parse failed (strategy 3): %s", exc)

    # Strategy 4: Last resort — try to salvage partial data via regex.
    salvaged = _salvage_partial_json(cleaned)
    if salvaged:
        logger.warning("JSON parsing required regex salvage (strategy 4). Partial data may be incomplete.")
        return salvaged

    # All strategies failed — log the malformed JSON for debugging.
    logger.error("Failed to parse Gemini JSON response after all repair strategies.")
    logger.error("Malformed JSON response (first 2000 chars): %s", raw_text[:2000])
    if len(raw_text) > 2000:
        logger.error("Malformed JSON response (last 500 chars): %s", raw_text[-500:])
    logger.debug("Full raw response length: %d chars", len(raw_text))
    raise ResponseParseError(
        "Invalid JSON returned by Gemini: unable to parse after multiple repair attempts. "
        "This may indicate a truncated or malformed response."
    )


def _salvage_partial_json(text: str) -> Optional[Dict[str, Any]]:
    """
    Last-resort strategy that uses regex to extract key-value pairs
    from partially valid JSON.

    This handles cases where the JSON is so malformed that structural
    parsing is impossible, but individual fields can still be recovered.

    Args:
        text: Raw JSON text.

    Returns:
        A dictionary of salvaged key-value pairs, or None if nothing
        could be extracted.
    """
    result: Dict[str, Any] = {}

    # Extract string values: "key": "value"
    string_pattern = re.compile(r'"(\w+)"\s*:\s*"([^"]*)"', re.DOTALL)
    for match in string_pattern.finditer(text):
        key = match.group(1)
        value = match.group(2)
        if key not in result:
            result[key] = value

    # Extract numeric values: "key": 123
    number_pattern = re.compile(r'"(\w+)"\s*:\s*(\d+\.?\d*)', re.DOTALL)
    for match in number_pattern.finditer(text):
        key = match.group(1)
        value_str = match.group(2)
        if key not in result:
            try:
                result[key] = float(value_str) if "." in value_str else int(value_str)
            except ValueError:
                pass

    # Extract boolean values: "key": true/false
    bool_pattern = re.compile(r'"(\w+)"\s*:\s*(true|false)', re.IGNORECASE)
    for match in bool_pattern.finditer(text):
        key = match.group(1)
        if key not in result:
            result[key] = match.group(2).lower() == "true"

    # Extract array values: "key": ["item1", "item2", ...]
    array_pattern = re.compile(r'"(\w+)"\s*:\s*\[([^\]]*)\]', re.DOTALL)
    for match in array_pattern.finditer(text):
        key = match.group(1)
        if key not in result:
            array_text = match.group(2)
            items = re.findall(r'"([^"]*)"', array_text)
            result[key] = items

    return result if result else None


def _normalize_optional_fields(data: Dict[str, Any]) -> None:
    """
    Type-normalizes optional XAI / forensic fields in-place.

    Ensures that numeric fields are numbers, boolean fields are booleans,
    and string fields are strings. Missing fields are left absent (they
    will be defaulted by the caller if needed) — this function only
    normalizes fields that ARE present but have the wrong type.

    Args:
        data: The parsed JSON dictionary (modified in-place).
    """
    # Numeric fields that should be int or float.
    numeric_int_fields = {
        "ai_probability", "ai_confidence", "phishing_score", "pwned_count",
        "jpeg_quality", "suspicious_links", "overall_score", "entropy",
    }
    numeric_float_fields = {"ela_score"}

    # Boolean fields.
    boolean_fields = {
        "ssl_valid", "malware_found", "spoofed_domain",
        "has_uppercase", "has_lowercase", "has_digit", "has_special",
    }

    for field in numeric_int_fields:
        if field in data and not isinstance(data[field], (int, float)):
            try:
                val = data[field]
                if isinstance(val, str):
                    val = val.replace("%", "").strip()
                data[field] = int(float(val))
            except (ValueError, TypeError):
                logger.debug("Could not normalize numeric field '%s': %s", field, data[field])
                data[field] = OPTIONAL_XAI_FIELDS.get(field, 0)

    for field in numeric_float_fields:
        if field in data and not isinstance(data[field], (int, float)):
            try:
                data[field] = float(data[field])
            except (ValueError, TypeError):
                logger.debug("Could not normalize float field '%s': %s", field, data[field])
                data[field] = OPTIONAL_XAI_FIELDS.get(field, 0.0)

    for field in boolean_fields:
        if field in data and not isinstance(data[field], bool):
            val = data[field]
            if isinstance(val, str):
                data[field] = val.strip().lower() in ("true", "yes", "1", "pass")
            else:
                data[field] = bool(val)


def validate_schema(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validates that the parsed dictionary contains the required shared schema keys.

    Missing keys are filled with sensible defaults so the application never crashes.
    Optional XAI / forensic fields are type-normalized and preserved — the parser
    never silently discards fields returned by Gemini.

    Args:
        data: The parsed JSON dictionary.

    Returns:
        A normalized dictionary with all required keys present and all
        optional XAI fields type-safe.
    """
    normalized: Dict[str, Any] = {}

    for key in REQUIRED_KEYS:
        if key not in data:
            logger.warning("Schema key '%s' missing from Gemini response; using default.", key)
        normalized[key] = data.get(key)

    # Apply type-safe defaults for required keys.
    if not isinstance(normalized.get("analysis_type"), str):
        normalized["analysis_type"] = "unknown"
    if not isinstance(normalized.get("risk_level"), str):
        normalized["risk_level"] = "Suspicious"
    if not isinstance(normalized.get("confidence"), (int, float)):
        normalized["confidence"] = 0
    if not isinstance(normalized.get("summary"), str):
        normalized["summary"] = "Analysis completed."
    if not isinstance(normalized.get("reasoning"), list):
        normalized["reasoning"] = []
    if not isinstance(normalized.get("recommendations"), list):
        normalized["recommendations"] = []
    if not isinstance(normalized.get("limitations"), list):
        normalized["limitations"] = []

    # Ensure confidence is a number.
    try:
        conf = normalized.get("confidence")
        if isinstance(conf, str):
            # Handle string representations like "85" or "85%"
            conf = conf.replace("%", "").strip()
            normalized["confidence"] = float(conf)
    except (ValueError, TypeError):
        normalized["confidence"] = 0

    # Normalize optional XAI / forensic fields in the raw data first.
    _normalize_optional_fields(data)

    # Preserve ALL extra feature-specific keys — never discard fields.
    for key, value in data.items():
        if key not in normalized:
            normalized[key] = value

    # Apply defaults for known optional XAI fields that are still missing,
    # so the frontend and XAI formatter always have consistent values.
    for field, default in OPTIONAL_XAI_FIELDS.items():
        if field not in normalized or normalized[field] is None:
            normalized[field] = default

    return normalized


def parse_and_validate(raw_text: str) -> Dict[str, Any]:
    """
    Convenience wrapper that parses and validates in one step.

    Args:
        raw_text: The raw text returned by the Gemini model.

    Returns:
        A normalized, schema-validated dictionary.
    """
    data = parse_json_response(raw_text)
    return validate_schema(data)


def error_response(analysis_type: str, error_message: str) -> Dict[str, Any]:
    """
    Builds a structured error JSON that matches the shared schema.

    Used when Gemini fails so the application never crashes and always
    returns a consistent shape to the frontend.

    Args:
        analysis_type: The feature that failed (e.g. "website").
        error_message: A human-readable description of the error.

    Returns:
        A schema-compliant error dictionary.
    """
    return {
        "analysis_type": analysis_type,
        "risk_level": "Suspicious",
        "confidence": 0,
        "summary": f"Analysis could not be completed: {error_message}",
        "reasoning": ["Gemini analysis engine encountered an error."],
        "recommendations": ["Please retry the analysis. If the issue persists, verify your API key and quota."],
        "limitations": ["No automated assessment was performed due to an engine error."],
        "explanation_markdown": (
            "## Analysis Error\n\n"
            f"**Error:** {error_message}\n\n"
            "The AI analysis engine could not complete this scan. "
            "Please try again. If the problem persists, check your "
            "Gemini API key and quota.\n"
        ),
    }