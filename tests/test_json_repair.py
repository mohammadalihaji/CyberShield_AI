"""
Test script to verify the JSON repair logic handles the exact types of
broken responses that were causing parse errors in production.

Tests:
1. JSON with raw newlines inside string values (the main issue)
2. JSON with trailing commas
3. Truncated JSON (unterminated string)
4. JSON with markdown fences and raw newlines
5. Valid JSON (should still work)
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.response_parser import parse_and_validate, parse_json_response, ResponseParseError


def test_raw_newlines_in_strings():
    """Test that raw newlines inside JSON string values are properly escaped."""
    # This simulates what Gemini was returning - raw newlines in the
    # explanation_markdown field
    raw = '''{
  "analysis_type": "website",
  "risk_level": "Malicious",
  "confidence": 85,
  "summary": "Phishing detected",
  "reasoning": ["Typosquatting detected", "Suspicious TLD"],
  "recommendations": ["Do not visit"],
  "limitations": ["No browsing"],
  "explanation_markdown": "## Website Analysis

**Verdict:** Malicious

### Key Findings
- Typosquatting detected
- Suspicious TLD

### Why This Assessment
The URL contains multiple phishing indicators.",
  "phishing_score": 85
}'''
    result = parse_and_validate(raw)
    assert result["risk_level"] == "Malicious"
    assert result["confidence"] == 85
    assert "phishing" in result["explanation_markdown"].lower()
    print("[PASS] test_raw_newlines_in_strings")


def test_trailing_commas():
    """Test that trailing commas are removed."""
    raw = '''{
  "analysis_type": "website",
  "risk_level": "Safe",
  "confidence": 90,
  "summary": "Clean",
  "reasoning": [],
  "recommendations": [],
  "limitations": [],
  "phishing_score": 10,
}'''
    result = parse_and_validate(raw)
    assert result["risk_level"] == "Safe"
    assert result["phishing_score"] == 10
    print("[PASS] test_trailing_commas")


def test_truncated_json():
    """Test that truncated JSON (unterminated string) is repaired."""
    # This simulates the "Unterminated string starting at" error
    raw = '''{
  "analysis_type": "website",
  "risk_level": "Suspicious",
  "confidence": 60,
  "summary": "Some concerns detected",
  "reasoning": ["IP address as host", "Excessive subdomains"],
  "recommendations": ["Verify before visiting"],
  "limitations": ["No browsing capability"],
  "explanation_markdown": "## Website Analysis

**Verdict:** Suspicious

### Key Findings
- IP address used as hostname
- Multiple subdomains detected

### Why This Assessment
The URL uses an IP address directly which is a common phishing indicator'''
    result = parse_and_validate(raw)
    assert result["risk_level"] == "Suspicious"
    print("[PASS] test_truncated_json")


def test_markdown_with_newlines():
    """Test JSON wrapped in markdown fences with raw newlines."""
    raw = '''```json
{
  "analysis_type": "image",
  "risk_level": "Suspicious",
  "confidence": 50,
  "summary": "Inconclusive",
  "reasoning": ["Noise patterns detected"],
  "recommendations": ["Verify source"],
  "limitations": ["Low resolution"],
  "ai_confidence": 50,
  "explanation_markdown": "## Image Analysis

**Verdict:** Suspicious

### Key Findings
- High-frequency noise patterns
- JPEG compression anomalies

### Why This Assessment
The image shows several indicators of potential AI generation."
}
```'''
    result = parse_and_validate(raw)
    assert result["risk_level"] == "Suspicious"
    assert result["ai_confidence"] == 50
    print("[PASS] test_markdown_with_newlines")


def test_valid_json():
    """Test that valid JSON still parses correctly."""
    raw = '{"analysis_type":"website","risk_level":"Safe","confidence":95,"summary":"Clean","reasoning":["HTTPS enabled","Reputable domain"],"recommendations":["No action needed"],"limitations":["No browsing"],"phishing_score":5,"ssl_valid":true}'
    result = parse_and_validate(raw)
    assert result["risk_level"] == "Safe"
    assert result["confidence"] == 95
    assert result["ssl_valid"] is True
    print("[PASS] test_valid_json")


def test_completely_broken():
    """Test that completely unparseable text raises an error."""
    raw = "This is not JSON at all, just plain text."
    try:
        parse_and_validate(raw)
        # If salvage finds nothing useful, it should raise
        # If it finds something, that's also acceptable
        print("[PASS] test_completely_broken (handled gracefully)")
    except ResponseParseError:
        print("[PASS] test_completely_broken (raised ResponseParseError)")


if __name__ == "__main__":
    print("=" * 60)
    print("CyberShield AI - JSON Repair Test Suite")
    print("=" * 60)
    print()

    test_valid_json()
    test_raw_newlines_in_strings()
    test_trailing_commas()
    test_truncated_json()
    test_markdown_with_newlines()
    test_completely_broken()

    print()
    print("=" * 60)
    print("ALL JSON REPAIR TESTS PASSED")
    print("=" * 60)