from typing import Dict, Any, List, Tuple


def generate_security_evidence(
    url_features: Dict[str, Any],
    page_features: Dict[str, Any],
    redirect_features: Dict[str, Any],
    page_available: bool = True
) -> Tuple[List[Dict[str, Any]], List[str], List[str]]:
    """
    Generates deterministic, human-readable security indicators from extracted features.
    Returns:
      - structured_evidence: List of { 'type': 'risk'|'trusted'|'neutral', 'category': str, 'text': str }
      - positive_indicators: List of strings (clean features)
      - risk_indicators: List of strings (suspicious features)
    """
    structured: List[Dict[str, Any]] = []
    positive: List[str] = []
    risk: List[str] = []

    # 1. URL Analysis Evidence
    if url_features.get("is_https"):
        positive.append("HTTPS TLS encryption is used on the URL")
        structured.append({"type": "trusted", "category": "URL", "text": "HTTPS encryption active"})
    else:
        risk.append("Unencrypted HTTP scheme used (lacks SSL/TLS transport security)")
        structured.append({"type": "risk", "category": "URL", "text": "Unencrypted HTTP scheme used"})

    if url_features.get("is_ip_address"):
        risk.append("IP address is used directly as hostname instead of a standard domain name")
        structured.append({"type": "risk", "category": "URL", "text": "IP address used as hostname"})

    if url_features.get("is_punycode"):
        risk.append("Punycode (xn--) internationalized domain detected (potential homograph impersonation)")
        structured.append({"type": "risk", "category": "URL", "text": "Punycode / homograph domain detected"})

    if url_features.get("has_at_symbol"):
        risk.append("URL contains '@' credential symbol used to disguise actual destination host")
        structured.append({"type": "risk", "category": "URL", "text": "'@' symbol in URL path"})

    if url_features.get("is_suspicious_port"):
        risk.append("Non-standard network port specified in URL")
        structured.append({"type": "risk", "category": "URL", "text": "Non-standard network port"})

    if url_features.get("suspicious_tld_indicator"):
        risk.append("High-risk top-level domain (TLD) commonly associated with phishing campaigns")
        structured.append({"type": "risk", "category": "URL", "text": "High-risk TLD detected"})

    if url_features.get("brand_in_subdomain_or_path"):
        risk.append("Target brand keyword appears in subdomain or path on an unrelated host domain")
        structured.append({"type": "risk", "category": "URL", "text": "Brand keyword on third-party domain"})

    if url_features.get("excessive_percent_encoding"):
        risk.append("Excessive percent-encoding obfuscation detected in URL parameters")
        structured.append({"type": "risk", "category": "URL", "text": "Excessive percent-encoding detected"})

    if url_features.get("is_shortened_url"):
        risk.append("Shortened URL service used to conceal target destination")
        structured.append({"type": "risk", "category": "URL", "text": "Shortened URL redirect wrapper"})

    if not url_features.get("is_ip_address") and not url_features.get("is_punycode") and not url_features.get("has_at_symbol") and not url_features.get("brand_in_subdomain_or_path"):
        positive.append("Standard URL and domain structure")

    # 2. Page & Form Analysis Evidence (if page was reachable)
    if page_available:
        # Form inputs
        has_pwd = page_features.get("has_password_field", 0) > 0
        has_otp = page_features.get("has_otp_field", 0) > 0
        has_payment = page_features.get("has_payment_field", 0) > 0
        has_cvv = page_features.get("has_cvv_field", 0) > 0
        has_pin = page_features.get("has_pin_field", 0) > 0
        has_pii = page_features.get("has_personal_info_field", 0) > 0

        if has_pwd:
            risk.append("Password input field detected on page")
            structured.append({"type": "risk", "category": "Form", "text": "Password input detected"})
        if has_otp:
            risk.append("OTP / two-factor verification code input detected on page")
            structured.append({"type": "risk", "category": "Form", "text": "OTP / 2FA verification input detected"})
        if has_payment:
            risk.append("Payment card number input detected on page")
            structured.append({"type": "risk", "category": "Form", "text": "Payment card input detected"})
        if has_cvv:
            risk.append("Card security code (CVV/CVC) input detected on page")
            structured.append({"type": "risk", "category": "Form", "text": "CVV/CVC input detected"})
        if has_pin:
            risk.append("PIN / security pass-code input detected on page")
            structured.append({"type": "risk", "category": "Form", "text": "PIN input detected"})
        if has_pii:
            risk.append("Sensitive personal identification input detected (SSN / National ID / DOB)")
            structured.append({"type": "risk", "category": "Form", "text": "Personal identity input detected"})

        if not (has_pwd or has_otp or has_payment or has_cvv or has_pin or has_pii):
            positive.append("No password, OTP, payment card, or sensitive credential inputs detected")
            structured.append({"type": "trusted", "category": "Form", "text": "No credential/payment inputs detected"})

        # Form actions
        if page_features.get("has_external_form_submit", 0) > 0:
            risk.append("Form submits collected data to an external, unrelated destination domain")
            structured.append({"type": "risk", "category": "Form", "text": "Form submits to external domain"})
        else:
            positive.append("No external form submission detected")
            structured.append({"type": "trusted", "category": "Form", "text": "No external form submission"})

        if page_features.get("has_insecure_form_action", 0) > 0:
            risk.append("HTTPS page contains form submitting to unencrypted HTTP destination")
            structured.append({"type": "risk", "category": "Form", "text": "Insecure HTTP form action on HTTPS page"})

        if page_features.get("has_mailto_form_action", 0) > 0:
            risk.append("Form action transmits form submission directly via mailto: email")
            structured.append({"type": "risk", "category": "Form", "text": "Mailto form submission handler"})

        # Script behaviors
        has_eval = page_features.get("has_eval", 0) > 0
        has_doc_write = page_features.get("has_document_write", 0) > 0
        has_tamper = page_features.get("has_event_tampering", 0) > 0
        has_b64 = page_features.get("has_base64_payload", 0) > 0

        if has_eval or has_doc_write:
            risk.append("Dynamic code execution or document.write() DOM manipulation in scripts")
            structured.append({"type": "risk", "category": "Script", "text": "Dynamic eval/document.write in scripts"})

        if has_tamper:
            risk.append("Right-click prevention or context-menu tampering detected")
            structured.append({"type": "risk", "category": "Script", "text": "Context menu / copy prevention detected"})

        if has_b64:
            risk.append("Obfuscated Base64-encoded payload strings found inside inline script blocks")
            structured.append({"type": "risk", "category": "Script", "text": "Base64 obfuscated script blocks"})

        if not (has_eval or has_doc_write or has_tamper or has_b64):
            positive.append("No obfuscated scripts or event tampering detected")

        # Iframes
        if page_features.get("has_hidden_iframe", 0) > 0:
            risk.append("Hidden or zero-dimension iframe element detected in page DOM")
            structured.append({"type": "risk", "category": "DOM", "text": "Hidden iframe detected"})
        else:
            positive.append("No hidden or zero-dimension iframes detected")

        # Executables / Downloads
        if page_features.get("has_executable_download", 0) > 0:
            risk.append("Direct link to binary executable or installer file (.exe, .apk, .msi, .scr, etc.) detected")
            structured.append({"type": "risk", "category": "Resource", "text": "Direct executable download link found"})

        # Redirects
        if redirect_features.get("has_https_downgrade"):
            risk.append("Redirect chain downgraded secure HTTPS connection to unencrypted HTTP")
            structured.append({"type": "risk", "category": "Redirect", "text": "HTTPS to HTTP downgrade during redirect"})

        if redirect_features.get("suspicious_redirect_pattern"):
            risk.append("Multiple cross-domain redirect hops detected during navigation")
            structured.append({"type": "risk", "category": "Redirect", "text": "Multiple cross-domain redirects"})
        elif redirect_features.get("redirect_count", 0) == 0:
            positive.append("Direct navigation with no redirect hops")
    else:
        structured.append({"type": "neutral", "category": "Fetcher", "text": "Webpage content was unreachable; assessment based on URL telemetry"})

    return structured, positive, risk
