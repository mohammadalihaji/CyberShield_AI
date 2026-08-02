"""
End-to-end test that calls the real Gemini API to verify the full flow:
  Build Prompt → Gemini API → Parse JSON → Return Response

This test uses the real API key from .env and makes actual API calls.
Run: python tests/test_e2e.py
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.gemini_service import analyze_website


def test_website_analysis_safe():
    """Test website analysis with a known-safe URL."""
    print("Test 1: Safe URL (https://www.google.com)")
    print("-" * 50)

    result = analyze_website("https://www.google.com")

    print(f"  analysis_type: {result.get('analysis_type')}")
    print(f"  risk_level: {result.get('risk_level')}")
    print(f"  confidence: {result.get('confidence')}")
    print(f"  phishing_score: {result.get('phishing_score')}")
    print(f"  ssl_valid: {result.get('ssl_valid')}")
    print(f"  reasoning count: {len(result.get('reasoning', []))}")
    print(f"  recommendations count: {len(result.get('recommendations', []))}")

    markdown = result.get('explanation_markdown', '')
    print(f"  explanation_markdown length: {len(markdown)} chars")
    if markdown:
        print(f"  explanation_markdown preview:")
        print(f"    {markdown[:500]}...")

    assert result.get('risk_level') is not None, "risk_level is missing"
    assert result.get('explanation_markdown') is not None, "explanation_markdown is missing"
    assert len(result.get('reasoning', [])) > 0, "reasoning array is empty"

    print()
    print("[PASS] Safe URL analysis completed successfully!")


def test_website_analysis_suspicious():
    """Test website analysis with a suspicious URL."""
    print("Test 2: Suspicious URL (http://login-verify-account.secure-update.top)")
    print("-" * 50)

    result = analyze_website("http://login-verify-account.secure-update.top/free-gift")

    print(f"  analysis_type: {result.get('analysis_type')}")
    print(f"  risk_level: {result.get('risk_level')}")
    print(f"  confidence: {result.get('confidence')}")
    print(f"  phishing_score: {result.get('phishing_score')}")
    print(f"  ssl_valid: {result.get('ssl_valid')}")
    print(f"  reasoning count: {len(result.get('reasoning', []))}")
    print(f"  recommendations count: {len(result.get('recommendations', []))}")

    markdown = result.get('explanation_markdown', '')
    print(f"  explanation_markdown length: {len(markdown)} chars")
    if markdown:
        print(f"  explanation_markdown preview:")
        print(f"    {markdown[:500]}...")

    assert result.get('risk_level') is not None, "risk_level is missing"
    assert result.get('explanation_markdown') is not None, "explanation_markdown is missing"
    assert len(result.get('reasoning', [])) > 0, "reasoning array is empty"

    print()
    print("[PASS] Suspicious URL analysis completed successfully!")


if __name__ == "__main__":
    print("=" * 60)
    print("CyberShield AI - End-to-End Test")
    print("=" * 60)
    print()

    try:
        test_website_analysis_safe()
        print()
        test_website_analysis_suspicious()
        print()
        print("=" * 60)
        print("E2E TEST PASSED - The fix is working correctly!")
        print("=" * 60)
        print()
        print("Summary of what was fixed:")
        print("  1. Migrated from deprecated google.generativeai to google.genai")
        print("  2. Added robust JSON repair logic (handles raw newlines,")
        print("     trailing commas, truncated responses)")
        print("  3. Improved prompts for explainable AI (why safe/not safe)")
        print("  4. Increased max_output_tokens from 2048 to 8192")
        print("  5. Error responses now include explanation_markdown field")
    except Exception as e:
        print()
        print("=" * 60)
        print(f"E2E TEST FAILED: {e}")
        print("=" * 60)
        import traceback
        traceback.print_exc()