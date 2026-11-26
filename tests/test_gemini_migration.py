"""
Test script to verify the Gemini migration components work correctly.
Tests the response parser, prompt manager, and config without needing a live API key.
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_response_parser():
    """Test the JSON response parser with various inputs."""
    from services.response_parser import parse_and_validate, error_response, ResponseParseError

    # Test 1: Valid JSON with extra fields
    raw1 = '{"analysis_type":"website","risk_level":"Malicious","confidence":85,"summary":"Phishing detected","reasoning":["Typosquatting"],"recommendations":["Avoid"],"limitations":["No browsing"],"phishing_score":85,"ssl_valid":false}'
    result1 = parse_and_validate(raw1)
    assert result1["risk_level"] == "Malicious"
    assert result1["phishing_score"] == 85
    assert result1["ssl_valid"] is False
    assert "analysis_type" in result1
    print("[PASS] test_response_parser: valid JSON with extra fields")

    # Test 2: JSON wrapped in markdown fences
    raw2 = '```json\n{"analysis_type":"email","risk_level":"Safe","confidence":90,"summary":"Clean","reasoning":[],"recommendations":[],"limitations":[]}\n```'
    result2 = parse_and_validate(raw2)
    assert result2["risk_level"] == "Safe"
    assert result2["confidence"] == 90
    print("[PASS] test_response_parser: markdown-fenced JSON")

    # Test 3: JSON with surrounding prose
    raw3 = 'Here is the analysis:\n{"analysis_type":"image","risk_level":"Suspicious","confidence":50,"summary":"Inconclusive","reasoning":["Noise"],"recommendations":["Verify"],"limitations":["Low resolution"]}\nDone.'
    result3 = parse_and_validate(raw3)
    assert result3["risk_level"] == "Suspicious"
    print("[PASS] test_response_parser: JSON with surrounding prose")

    # Test 4: Missing schema keys get defaults
    raw4 = '{"analysis_type":"password","risk_level":"Weak"}'
    result4 = parse_and_validate(raw4)
    assert result4["risk_level"] == "Weak"
    assert result4["confidence"] == 0
    assert result4["reasoning"] == []
    print("[PASS] test_response_parser: missing keys get defaults")

    # Test 5: Empty response raises error
    try:
        parse_and_validate("")
        assert False, "Should have raised ResponseParseError"
    except ResponseParseError:
        print("[PASS] test_response_parser: empty response raises error")

    # Test 6: error_response produces valid schema
    err = error_response("image", "timeout")
    assert err["risk_level"] == "Suspicious"
    assert err["confidence"] == 0
    assert "timeout" in err["summary"]
    print("[PASS] test_response_parser: error_response produces valid schema")


def test_prompt_manager():
    """Test that all prompts are generated and contain key instructions."""
    from services import prompt_manager

    # Website prompt
    wp = prompt_manager.website_prompt("https://example.com")
    assert "Cybersecurity Threat Intelligence Analyst" in wp
    assert "phishing" in wp.lower()
    assert "JSON" in wp
    assert "https://example.com" in wp
    print("[PASS] test_prompt_manager: website_prompt")

    # Email prompt
    ep = prompt_manager.email_prompt("admin@fake.com", "Click here urgently!")
    assert "Email Security Analyst" in ep
    assert "phishing" in ep.lower()
    assert "admin@fake.com" in ep
    print("[PASS] test_prompt_manager: email_prompt")

    # Image prompt
    ip = prompt_manager.image_prompt("test.png")
    assert "Digital Forensics Analyst" in ip
    assert "AI-generated" in ip
    assert "test.png" in ip
    print("[PASS] test_prompt_manager: image_prompt")

    # Password prompt now expects anonymized metadata (never the raw password).
    metadata = {
        "length": 10,
        "has_uppercase": True,
        "has_lowercase": True,
        "has_digit": True,
        "has_special": True,
        "entropy": 60.0,
        "risk": "Strong",
        "pwned_count": 0,
        "common_patterns": [],
        "is_common_word": False,
        "keyboard_walk": False,
    }
    pp = prompt_manager.password_prompt(metadata)
    assert "Security Engineer" in pp
    assert "entropy" in pp.lower()
    # The raw password MUST NOT appear in the prompt (privacy guarantee).
    assert "MyP@ssw0rd" not in pp
    print("[PASS] test_prompt_manager: password_prompt (anonymized metadata)")

    # Advisor prompt
    ap = prompt_manager.advisor_prompt({"mfa": "no", "pw_reuse": "yes"})
    assert "Cybersecurity Advisor" in ap
    assert "mfa" in ap
    print("[PASS] test_prompt_manager: advisor_prompt")

    # Chat prompt
    cp = prompt_manager.chat_prompt("What is phishing?", [{"role": "user", "content": "hi"}])
    assert "CyberShield AI" in cp
    assert "What is phishing?" in cp
    assert "markdown" in cp.lower()
    print("[PASS] test_prompt_manager: chat_prompt")


def test_config():
    """Test that Gemini config loads from environment."""
    from config import Config

    assert Config.GEMINI_MODEL == "gemini-2.5-flash"
    assert Config.GEMINI_TEMPERATURE == 0.2
    assert Config.GEMINI_MAX_OUTPUT_TOKENS == 8192
    assert Config.GEMINI_TIMEOUT == 60
    print("[PASS] test_config: Gemini configuration loaded correctly")


def test_service_facade():
    """Test that the root facade exports all required functions."""
    import gemini_service

    assert hasattr(gemini_service, "analyze_website")
    assert hasattr(gemini_service, "analyze_email")
    assert hasattr(gemini_service, "analyze_image")
    assert hasattr(gemini_service, "analyze_password")
    assert hasattr(gemini_service, "get_security_advice")
    assert hasattr(gemini_service, "chat")
    assert hasattr(gemini_service, "process_chat_message")
    assert hasattr(gemini_service, "get_password_advice")
    print("[PASS] test_service_facade: all public methods exported")


def test_no_rule_based_logic():
    """Verify no legacy rule-based VERDICT generators remain in the service.

    NOTE: 'charset_size' / 'math.log2' / 'is_common_word' are intentionally
    present — they belong to _compute_password_metadata() which calculates
    ANONYMIZED metrics locally so the raw password never reaches Gemini.
    This is a privacy/security feature, not a rule-based verdict generator.
    """
    import services.gemini_service as gs

    # Read the source and check for rule-based patterns
    import inspect
    source = inspect.getsource(gs)

    forbidden = [
        "suspicious_keywords",
        "urgency_keywords",
        "common_words",
        "phishing_score +=",
        "pwned_count = 14209",
        "ai_confidence = 74",
        "GAN Grid",
    ]

    for pattern in forbidden:
        assert pattern not in source, f"Rule-based pattern found in service: {pattern}"

    print("[PASS] test_no_rule_based_logic: no legacy rule-based verdict generators in gemini_service")


if __name__ == "__main__":
    print("=" * 60)
    print("CyberShield AI - Gemini Migration Test Suite")
    print("=" * 60)
    print()

    test_config()
    test_response_parser()
    test_prompt_manager()
    test_service_facade()
    test_no_rule_based_logic()

    print()
    print("=" * 60)
    print("ALL TESTS PASSED")
    print("=" * 60)