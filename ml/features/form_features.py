import re
from urllib.parse import urlparse, urljoin
from typing import Dict, Any, List
from bs4 import BeautifulSoup
from ml.features.url_features import extract_base_domain

# Regex patterns for sensitive field detection in form inputs (names, ids, placeholders, aria-labels)
PASSWORD_REGEX = re.compile(r"(pass|pwd|password|passwd|passcode|secret)", re.IGNORECASE)
EMAIL_REGEX = re.compile(r"(email|mail|e-mail)", re.IGNORECASE)
USERNAME_REGEX = re.compile(r"(user|username|login|signin|sign-in|account|userid|member)", re.IGNORECASE)
OTP_REGEX = re.compile(r"(otp|2fa|mfa|verification|verify_code|vcode|auth_code|token|security_code|one_time|passcode)", re.IGNORECASE)
PAYMENT_REGEX = re.compile(r"(card|credit|debit|cardnumber|cc_num|cc-num|pan_no|card_num|expiry|exp_date)", re.IGNORECASE)
CVV_REGEX = re.compile(r"(cvv|cvc|ccv|cvv2|security_code|cid)", re.IGNORECASE)
PIN_REGEX = re.compile(r"(pin|atm_pin|secret_pin|mpin)", re.IGNORECASE)
PERSONAL_INFO_REGEX = re.compile(r"(ssn|social_security|aadhaar|tax_id|national_id|passport|dob|birth_date|birthdate|maiden_name)", re.IGNORECASE)


def extract_form_features(soup: BeautifulSoup, page_url: str) -> Dict[str, Any]:
    """
    Analyzes forms and input fields in static HTML without JavaScript execution.
    Extracts deterministic security indicators for sensitive inputs and form action destinations.
    """
    if not page_url:
        page_url = "https://unknown.domain"
    
    parsed_page = urlparse(page_url)
    page_host = parsed_page.hostname or ""
    page_base_domain = extract_base_domain(page_host)
    page_is_https = parsed_page.scheme.lower() == "https"

    forms = soup.find_all("form") if soup else []
    total_forms = len(forms)

    num_password = 0
    num_email = 0
    num_username = 0
    num_otp = 0
    num_payment = 0
    num_cvv = 0
    num_pin = 0
    num_personal_info = 0
    num_hidden = 0
    num_submit_btn = 0

    external_form_submits = 0
    empty_form_actions = 0
    mailto_form_actions = 0
    insecure_form_actions = 0
    domain_mismatches = 0
    form_details: List[Dict[str, Any]] = []

    # Also inspect standalone inputs not wrapped in <form> tags
    all_inputs = soup.find_all(["input", "textarea", "select"]) if soup else []
    
    for inp in all_inputs:
        inp_type = (inp.get("type") or "text").lower().strip()
        inp_name = (inp.get("name") or "").lower()
        inp_id = (inp.get("id") or "").lower()
        inp_ph = (inp.get("placeholder") or "").lower()
        inp_aria = (inp.get("aria-label") or "").lower()
        combined_attrs = f"{inp_name} {inp_id} {inp_ph} {inp_aria}"

        if inp_type == "password" or PASSWORD_REGEX.search(combined_attrs):
            num_password += 1
        elif inp_type == "email" or EMAIL_REGEX.search(combined_attrs):
            num_email += 1
        elif inp_type == "hidden":
            num_hidden += 1
        elif inp_type in ("submit", "button") or inp.name == "button":
            num_submit_btn += 1

        if USERNAME_REGEX.search(combined_attrs) and inp_type != "password":
            num_username += 1

        if OTP_REGEX.search(combined_attrs):
            num_otp += 1

        if PAYMENT_REGEX.search(combined_attrs):
            num_payment += 1

        if CVV_REGEX.search(combined_attrs):
            num_cvv += 1

        if PIN_REGEX.search(combined_attrs):
            num_pin += 1

        if PERSONAL_INFO_REGEX.search(combined_attrs):
            num_personal_info += 1

    # Form action & destination domain analysis
    for form in forms:
        action = (form.get("action") or "").strip()
        method = (form.get("method") or "get").upper()
        
        form_entry = {
            "action": action,
            "method": method,
            "is_external": False,
            "is_insecure": False,
            "is_empty": False
        }

        if not action or action in ("#", "about:blank", "javascript:void(0);", "javascript:;"):
            empty_form_actions += 1
            form_entry["is_empty"] = True
        elif action.lower().startswith("mailto:"):
            mailto_form_actions += 1
            form_entry["is_external"] = True
        else:
            # Resolve relative action URL against the current page URL
            resolved_action = urljoin(page_url, action)
            parsed_action = urlparse(resolved_action)
            action_host = parsed_action.hostname or ""
            action_base_domain = extract_base_domain(action_host)
            action_is_https = parsed_action.scheme.lower() == "https"

            if page_is_https and not action_is_https and parsed_action.scheme.lower() == "http":
                insecure_form_actions += 1
                form_entry["is_insecure"] = True

            # Domain mismatch check
            if action_base_domain and page_base_domain and action_base_domain != page_base_domain:
                external_form_submits += 1
                domain_mismatches += 1
                form_entry["is_external"] = True
                form_entry["action_domain"] = action_base_domain

        form_details.append(form_entry)

    return {
        "total_forms": total_forms,
        "has_password_field": 1 if num_password > 0 else 0,
        "num_password_fields": num_password,
        "has_email_field": 1 if num_email > 0 else 0,
        "num_email_fields": num_email,
        "has_username_field": 1 if num_username > 0 else 0,
        "num_username_fields": num_username,
        "has_otp_field": 1 if num_otp > 0 else 0,
        "num_otp_fields": num_otp,
        "has_payment_field": 1 if num_payment > 0 else 0,
        "num_payment_fields": num_payment,
        "has_cvv_field": 1 if num_cvv > 0 else 0,
        "num_cvv_fields": num_cvv,
        "has_pin_field": 1 if num_pin > 0 else 0,
        "num_pin_fields": num_pin,
        "has_personal_info_field": 1 if num_personal_info > 0 else 0,
        "num_personal_info_fields": num_personal_info,
        "num_hidden_inputs": num_hidden,
        "num_submit_buttons": num_submit_btn,
        "has_external_form_submit": 1 if external_form_submits > 0 else 0,
        "num_external_form_submits": external_form_submits,
        "has_empty_form_action": 1 if empty_form_actions > 0 else 0,
        "has_mailto_form_action": 1 if mailto_form_actions > 0 else 0,
        "has_insecure_form_action": 1 if insecure_form_actions > 0 else 0,
        "form_domain_mismatch_count": domain_mismatches,
        "forms_summary": form_details
    }
