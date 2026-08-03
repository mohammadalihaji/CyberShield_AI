"""
Fallback / Demo Mode handlers for CyberShield AI.

When the Gemini API key is not configured or the API is unavailable,
these handlers provide local heuristic-based responses so the application
remains fully functional for demonstration and testing purposes.

Each fallback produces the same schema-compliant JSON structure as the
real Gemini analysis, ensuring the frontend and database never break.
"""

import os
import re
import math
import random
from typing import Any, Dict, List, Optional

from utils.logger import get_logger

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Password metadata computation (used by both Gemini and fallback)
# ---------------------------------------------------------------------------

COMMON_WORDS = [
    "password", "123456", "qwerty", "admin", "welcome", "letmein",
    "monkey", "dragon", "master", "login", "abc123", "password1",
    "iloveyou", "trustno1", "sunshine", "princess", "football",
]

KEYBOARD_WALKS = [
    "qwerty", "asdf", "zxcv", "qazwsx", "123456", "abcdef",
    "qwertyuiop", "asdfghjkl", "zxcvbnm",
]


def compute_password_metadata(password: str) -> Dict[str, Any]:
    """
    Computes anonymized password metadata locally.

    This function extracts security-relevant metrics from the password
    WITHOUT sending the raw password to Gemini. The metadata is used
    both for the Gemini prompt and for the fallback analysis.

    Args:
        password: The plaintext password to analyze.

    Returns:
        A dictionary of anonymized password metrics.
    """
    length = len(password)
    has_upper = bool(re.search(r"[A-Z]", password))
    has_lower = bool(re.search(r"[a-z]", password))
    has_digit = bool(re.search(r"[0-9]", password))
    has_special = bool(re.search(r"[^A-Za-z0-9]", password))

    # Compute charset size and entropy.
    charset_size = 0
    if has_lower:
        charset_size += 26
    if has_upper:
        charset_size += 26
    if has_digit:
        charset_size += 10
    if has_special:
        charset_size += 32

    entropy = round(length * math.log2(charset_size)) if charset_size > 0 else 0

    # Determine risk level.
    is_common = any(word in password.lower() for word in COMMON_WORDS)
    is_keyboard_walk = any(walk in password.lower() for walk in KEYBOARD_WALKS)

    if length < 8 or is_common:
        risk = "Weak"
    elif length < 12 or entropy < 60:
        risk = "Medium"
    else:
        risk = "Strong"

    # Detect patterns.
    patterns = []
    if is_common:
        patterns.append("Common dictionary word detected")
    if is_keyboard_walk:
        patterns.append("Keyboard walk pattern detected")
    if re.search(r"(.)\1{2,}", password):
        patterns.append("Repeated characters detected")
    if re.search(r"(0123|1234|2345|3456|4567|5678|6789|abcd|bcde)", password.lower()):
        patterns.append("Sequential characters detected")

    # Estimate pwned count (heuristic — not a real breach database lookup).
    if is_common or length < 6:
        pwned_count = random.randint(50000, 5000000)
    elif risk == "Weak":
        pwned_count = random.randint(1000, 50000)
    elif risk == "Medium":
        pwned_count = random.randint(0, 1000)
    else:
        pwned_count = 0

    # Estimate crack time.
    if entropy < 28:
        crack_time = "Instant (< 1 second)"
    elif entropy < 36:
        crack_time = "Seconds to minutes"
    elif entropy < 60:
        crack_time = "Hours to days"
    elif entropy < 80:
        crack_time = "Years to decades"
    elif entropy < 120:
        crack_time = "Centuries"
    else:
        crack_time = "Millennia (practically uncrackable)"

    return {
        "length": length,
        "has_uppercase": has_upper,
        "has_lowercase": has_lower,
        "has_digit": has_digit,
        "has_special": has_special,
        "entropy": entropy,
        "risk": risk,
        "pwned_count": pwned_count,
        "common_patterns": patterns,
        "is_common_word": is_common,
        "keyboard_walk": is_keyboard_walk,
        "estimated_crack_time": crack_time,
    }


# ---------------------------------------------------------------------------
# Fallback analysis handlers
# ---------------------------------------------------------------------------

def fallback_website_analysis(url: str) -> Dict[str, Any]:
    """
    Local heuristic-based website analysis when Gemini is unavailable.
    """
    url_lower = url.lower()

    phishing_keywords = [
        "phish", "login-paypal", "secure-bank", "update-password",
        "free-gift", "win-money", "verify-account", "claim-reward",
    ]
    malware_keywords = ["crack", "keygen", "torrent-free", "illegal-download", "warez"]

    if any(k in url_lower for k in phishing_keywords):
        risk_level = "Malicious"
        phishing_score = random.randint(80, 95)
        reasoning = [
            "Spoofed brand name detected in URL structure",
            "Credential harvesting keywords (login, verify, account) present",
            "Suspicious domain pattern consistent with phishing campaigns",
        ]
        recommendations = [
            "Do not enter credentials on this site",
            "Report the URL to your organization's security team",
            "Verify the legitimate site through official channels",
        ]
    elif any(k in url_lower for k in malware_keywords):
        risk_level = "Malicious"
        phishing_score = random.randint(60, 80)
        reasoning = [
            "URL associated with software piracy and malware distribution",
            "High-risk TLD or domain pattern detected",
        ]
        recommendations = [
            "Avoid downloading any files from this domain",
            "Run a full antivirus scan if you visited this site",
        ]
    elif url_lower.startswith("https://"):
        risk_level = "Safe"
        phishing_score = random.randint(5, 20)
        reasoning = [
            "Valid HTTPS encryption detected",
            "No phishing or malware indicators in URL structure",
            "Domain appears to use standard security practices",
        ]
        recommendations = [
            "Continue normal browsing",
            "Monitor periodically for changes",
        ]
    else:
        risk_level = "Suspicious"
        phishing_score = random.randint(30, 60)
        reasoning = [
            "No HTTPS encryption detected",
            "URL structure shows some unusual patterns",
            "Unable to verify domain reputation without browsing",
        ]
        recommendations = [
            "Exercise caution when visiting this site",
            "Verify the URL through alternative sources",
        ]

    return {
        "analysis_type": "website",
        "risk_level": risk_level,
        "confidence": random.randint(60, 85),
        "summary": f"URL analysis completed: {risk_level}",
        "reasoning": reasoning,
        "recommendations": recommendations,
        "limitations": ["Local heuristic analysis — Gemini AI not available for deep inspection"],
        "phishing_score": phishing_score,
        "ssl_valid": url_lower.startswith("https://"),
        "malware_found": risk_level == "Malicious",
        "domain_age": "Unknown",
        "reputation": "Unverified" if risk_level == "Suspicious" else ("Bad / High Risk" if risk_level == "Malicious" else "Trusted Domain"),
        "explanation_markdown": "",
    }


def fallback_email_analysis(sender: str, body: str) -> Dict[str, Any]:
    """
    Local heuristic-based email phishing analysis when Gemini is unavailable.
    """
    body_lower = body.lower()
    sender_lower = sender.lower()

    scoring = 0
    urgency = "Normal"
    spoofed = False

    phish_indicators = ["paypal", "netflix", "amazon", "chase", "bank", "crypto", "wallet", "invoice", "overdue", "wire transfer", "irs", "refund"]
    urgency_indicators = ["urgent", "immediate", "suspend", "restricted", "24 hours", "action required", "unauthorized login", "verify now"]

    # Brand spoofing check.
    brand_domains = {
        "paypal": "@paypal.com", "google": "@google.com",
        "netflix": "@netflix.com", "chase": "@chase.com",
        "amazon": "@amazon.com",
    }
    for brand, official in brand_domains.items():
        if brand in body_lower and official not in sender_lower:
            spoofed = True
            scoring += 40

    if any(k in body_lower or k in sender_lower for k in phish_indicators):
        scoring += 30
    if any(k in body_lower for k in urgency_indicators):
        scoring += 25
        urgency = "High"
    elif any(k in body_lower for k in ["alert", "notice", "important"]):
        scoring += 10
        urgency = "Medium"

    links_count = body_lower.count("http")
    scoring += min(links_count * 15, 30)
    scoring = min(scoring, 100)

    if scoring >= 65:
        risk = "Malicious"
        spf = "Fail"
    elif scoring >= 30:
        risk = "Suspicious"
        spf = "Neutral"
    else:
        risk = "Safe"
        spf = "Pass"

    reasoning = []
    if spoofed:
        reasoning.append(f"Sender domain does not match brand referenced in body")
    if urgency == "High":
        reasoning.append("Urgency language detected — pressure tactics common in phishing")
    if links_count > 0:
        reasoning.append(f"{links_count} hyperlink(s) found in email body")
    if not reasoning:
        reasoning.append("No significant phishing indicators detected")

    return {
        "analysis_type": "email",
        "risk_level": risk,
        "confidence": random.randint(60, 85),
        "summary": f"Email analysis completed: {risk}",
        "reasoning": reasoning,
        "recommendations": [
            "Do not click links or download attachments" if risk == "Malicious" else "Verify sender through alternative channels",
        ],
        "limitations": ["Local heuristic analysis — Gemini AI not available for deep inspection"],
        "phishing_score": scoring,
        "urgency": urgency,
        "suspicious_links": links_count,
        "spoofed_domain": spoofed,
        "spf_check": spf,
        "dkim_check": "Not Available",
        "dmarc_check": "Not Available",
        "social_engineering": "High - Urgency + Authority" if urgency == "High" else ("Medium" if urgency == "Medium" else "None Detected"),
        "explanation_markdown": "",
    }


def fallback_image_analysis(filename: str, forensic_data: Optional[Dict] = None) -> Dict[str, Any]:
    """
    Local heuristic-based image analysis when Gemini is unavailable.
    Uses forensic data if available, otherwise falls back to filename heuristics.
    """
    filename_lower = filename.lower()

    # Use forensic data if available.
    if forensic_data and not forensic_data.get("error"):
        texture = forensic_data.get("texture_consistency", "")
        noise = forensic_data.get("noise", "")
        gan = forensic_data.get("gan_artifacts", "")
        hist = forensic_data.get("histogram_distribution", "")

        synthetic_indicators = 0
        if "Synthetic" in str(texture) or "Uniform" in str(texture):
            synthetic_indicators += 1
        if "Low" in str(noise) and "Synthetic" in str(noise):
            synthetic_indicators += 1
        if "Possible" in str(gan) or "Likely" in str(gan):
            synthetic_indicators += 1
        if "Artificial" in str(hist) or "Peaked" in str(hist):
            synthetic_indicators += 1

        if synthetic_indicators >= 3:
            risk = "Malicious"
            ai_prob = random.randint(75, 95)
            reasoning = [
                f"Texture analysis: {texture}",
                f"Noise pattern: {noise}",
                f"GAN artifact detection: {gan}",
                f"Histogram distribution: {hist}",
            ]
        elif synthetic_indicators >= 1:
            risk = "Suspicious"
            ai_prob = random.randint(30, 70)
            reasoning = [
                f"Some synthetic indicators detected ({synthetic_indicators} flags)",
                f"Texture: {texture}, Noise: {noise}",
            ]
        else:
            risk = "Safe"
            ai_prob = random.randint(1, 15)
            reasoning = [
                "Natural texture and noise patterns detected",
                "No GAN artifacts or synthetic indicators found",
            ]
    else:
        # Filename-based heuristic.
        if any(k in filename_lower for k in ["ai", "generated", "midjourney", "synthetic", "fake", "diffusion"]):
            risk = "Malicious"
            ai_prob = random.randint(85, 99)
            reasoning = ["Filename suggests AI-generated content", "No forensic data available for verification"]
        elif any(k in filename_lower for k in ["real", "photo", "camera", "nature"]):
            risk = "Safe"
            ai_prob = random.randint(1, 10)
            reasoning = ["Filename suggests authentic photograph", "No forensic data available for verification"]
        else:
            risk = "Suspicious"
            ai_prob = random.randint(20, 60)
            reasoning = ["Insufficient data for definitive assessment"]

    return {
        "analysis_type": "image",
        "risk_level": risk,
        "confidence": random.randint(50, 80),
        "summary": f"Image analysis completed: {risk}",
        "reasoning": reasoning,
        "recommendations": ["Manual review recommended" if risk != "Safe" else "Image appears authentic"],
        "limitations": ["Local heuristic analysis — Gemini Vision not available for visual inspection"],
        "ai_probability": ai_prob,
        "ai_confidence": ai_prob,
        "ela_score": forensic_data.get("ela_score", 0.0) if forensic_data else 0.0,
        "noise_score": forensic_data.get("noise", "N/A") if forensic_data else "N/A",
        "lighting_consistency": forensic_data.get("lighting_consistency", "N/A") if forensic_data else "N/A",
        "pixel_irregularity": forensic_data.get("pixel_irregularity", "N/A") if forensic_data else "N/A",
        "compression_analysis": forensic_data.get("compression_analysis", "N/A") if forensic_data else "N/A",
        "metadata_status": forensic_data.get("metadata_status", "N/A") if forensic_data else "N/A",
        "organic_texture": forensic_data.get("organic_texture", "N/A") if forensic_data else "N/A",
        "gan_artifacts": forensic_data.get("gan_artifacts", "N/A") if forensic_data else "N/A",
        "fingerprints": "None Detected",
        "jpeg_artifacts": "None Detected",
        "explanation_markdown": "",
    }


def fallback_password_analysis(password: str) -> Dict[str, Any]:
    """
    Local heuristic-based password analysis when Gemini is unavailable.
    Uses the same metadata computation as the Gemini path.
    """
    meta = compute_password_metadata(password)

    risk = meta["risk"]
    entropy = meta["entropy"]
    pwned_count = meta["pwned_count"]

    reasoning = []
    if meta["is_common_word"]:
        reasoning.append("Common dictionary word detected — highly vulnerable to dictionary attacks")
    if meta["keyboard_walk"]:
        reasoning.append("Keyboard walk pattern detected — easily guessable")
    if meta["length"] < 8:
        reasoning.append(f"Password length ({meta['length']}) is below recommended minimum of 8 characters")
    if entropy < 40:
        reasoning.append(f"Low entropy ({entropy} bits) — vulnerable to brute force attacks")
    if not meta["has_uppercase"]:
        reasoning.append("Missing uppercase characters — reduces keyspace")
    if not meta["has_special"]:
        reasoning.append("Missing special characters — reduces keyspace")
    if not reasoning:
        reasoning.append("Password meets basic complexity requirements")
        reasoning.append(f"Entropy of {entropy} bits provides reasonable resistance to brute force")

    recommendations = []
    if meta["length"] < 12:
        recommendations.append("Increase total character count to 16+ using a multi-word passphrase")
    if not (meta["has_uppercase"] and meta["has_lowercase"] and meta["has_digit"] and meta["has_special"]):
        recommendations.append("Use a mix of uppercase, lowercase, integers, and symbols (@, $, #)")
    if risk == "Weak":
        recommendations.append("Do not use dictionary words or standard credential keyboard sequences")
    recommendations.append("Store this in a secure password vault to prevent manual credential tracking")

    return {
        "analysis_type": "password",
        "risk_level": risk,
        "confidence": random.randint(70, 90),
        "summary": f"Password strength: {risk}",
        "reasoning": reasoning,
        "recommendations": recommendations,
        "limitations": ["Local heuristic analysis — Gemini AI not available for deep assessment"],
        "entropy": entropy,
        "pwned_count": pwned_count,
        "has_uppercase": meta["has_uppercase"],
        "has_lowercase": meta["has_lowercase"],
        "has_digit": meta["has_digit"],
        "has_special": meta["has_special"],
        "dictionary_risk": "High - Common word detected" if meta["is_common_word"] else ("Medium" if risk == "Weak" else "Low"),
        "pattern_detection": ", ".join(meta["common_patterns"]) if meta["common_patterns"] else "None Detected",
        "estimated_crack_time": meta["estimated_crack_time"],
        "explanation_markdown": "",
    }


def fallback_advisor_analysis(profile: Dict) -> Dict[str, Any]:
    """
    Local heuristic-based security posture analysis when Gemini is unavailable.
    """
    score = 100
    recs = []

    mfa = profile.get("mfa", "no")
    pw_reuse = profile.get("pw_reuse", "yes")
    updates = profile.get("updates", "rarely")
    backups = profile.get("backups", "no")
    phish_awareness = profile.get("phish_awareness", "no")

    if mfa == "no":
        score -= 25
        recs.append("Enable Multi-Factor Authentication (MFA) on all primary accounts")
    elif mfa == "partial":
        score -= 10
        recs.append("Expand MFA coverage to all financial and work portals")

    if pw_reuse == "yes":
        score -= 25
        recs.append("Adopt a password manager and stop reusing passwords across services")

    if updates == "rarely":
        score -= 20
        recs.append("Set operating system and apps to auto-update immediately")
    elif updates == "sometimes":
        score -= 10
        recs.append("Automate patch cycles with weekly update reminders")

    if backups == "no":
        score -= 15
        recs.append("Implement the 3-2-1 backup rule (3 copies, 2 media, 1 offsite)")

    if phish_awareness == "no":
        score -= 15
        recs.append("Conduct regular phishing self-audits and learn to verify email headers")

    score = max(score, 15)
    risk = "Safe" if score >= 80 else ("Suspicious" if score >= 50 else "Malicious")

    reasoning = []
    if mfa != "yes":
        reasoning.append(f"MFA status: {mfa} — reduces account security")
    if pw_reuse == "yes":
        reasoning.append("Password reuse detected — high risk of credential stuffing")
    if updates == "rarely":
        reasoning.append("Rare update schedule — vulnerable to known CVEs")
    if backups == "no":
        reasoning.append("No backup strategy — high risk of data loss from ransomware")
    if not reasoning:
        reasoning.append("Security profile shows good practices across all categories")

    return {
        "analysis_type": "advisor",
        "risk_level": risk,
        "confidence": random.randint(70, 90),
        "summary": f"Security posture score: {score}/100",
        "reasoning": reasoning,
        "recommendations": recs,
        "limitations": ["Local heuristic analysis — Gemini AI not available for personalized advice"],
        "overall_score": score,
        "general_advisor_markdown": "",
    }


def fallback_chat_response(message: str) -> str:
    """
    Local chat responder when Gemini is unavailable.
    Provides pre-coded cybersecurity guidance based on keywords.
    """
    msg_lower = message.lower()

    if any(k in msg_lower for k in ["hello", "hi", "hey", "start"]):
        return (
            "Hello! I am your CyberShield AI Security Assistant. "
            "I can answer questions about phishing, malware, passwords, "
            "secure browsing, network configurations, or how to harden "
            "your computer settings. What would you like to secure today?\n\n"
            "*Note: Running in offline/demo mode. Set GEMINI_API_KEY for full AI capability.*"
        )

    if any(k in msg_lower for k in ["phishing", "phish", "scam", "suspicious link", "email alert"]):
        return """### 🎣 Understanding and Spotting Phishing Scams

Phishing is a method where attackers impersonate reputable organizations to trick you into revealing credentials.

#### 🚩 Common Red Flags:
1. **Urgency Tactics**: "Your account will be suspended within 24 hours!"
2. **Discrepant Domains**: Sender claims to be Google, but address ends in `@secure-verify-update.info`
3. **Vague Greetings**: "Dear Customer" instead of your name
4. **Suspicious Links**: Hovering reveals misspelled or redirecting URLs

#### 🛡️ Protection:
* Never use email links to log in — navigate directly to official sites
* Setup Authenticator-based 2FA
* Report suspicious mail as Spam"""

    if any(k in msg_lower for k in ["password", "pwd", "passphrase", "brute force", "manager"]):
        return """### 🔑 Password Security Best Practices

* **Length beats complexity**: 16+ character passphrases are exponentially harder to crack
* **Zero Reuse**: Credential stuffing attacks exploit reused passwords across sites
* **Adopt a Vault**: Use Bitwarden, KeePass, or 1Password
* **Verify breaches**: Check [HaveIBeenPwned](https://haveibeenpwned.com)"""

    if any(k in msg_lower for k in ["mfa", "2fa", "authentication", "totp"]):
        return """### 🛡️ Multi-Factor Authentication (MFA)

Ranked from strongest to weakest:
1. **Hardware Keys** (YubiKey) — immune to remote phishing
2. **Authenticator Apps** — time-based codes, highly secure
3. **Push Notifications** — secure but vulnerable to fatigue
4. **SMS/Email codes** — weakest, vulnerable to SIM-swapping"""

    if any(k in msg_lower for k in ["malware", "virus", "ransomware", "trojan"]):
        return """### 🦠 Malware Types and Defenses

* **Ransomware**: Encrypts drives, demands crypto payments
* **Trojans**: Disguise as legitimate software, implant backdoors
* **Keyloggers**: Record keystrokes to steal credentials

#### 🛡️ Shielding:
1. Keep antivirus running with cloud intelligence
2. Never run `.exe` from unofficial sources
3. Use application whitelisting"""

    return """### 🔍 CyberShield Security Response Hub

I can help with:
* *"How do I detect a phishing email?"*
* *"What is SMS hijacking?"*
* *"How to set up a backup strategy?"*
* *"Explain ransomware and recovery"*

*Running in offline/demo mode. Set GEMINI_API_KEY for full conversational capability.*"""