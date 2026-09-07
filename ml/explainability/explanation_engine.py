from typing import Dict, Any, List
from ml.explainability.evidence_rules import generate_security_evidence


class ExplanationEngine:
    """
    Generates explainable AI (XAI) narratives, evidence bullet points, and transparency summaries
    for ML website security assessments.
    """

    @staticmethod
    def generate_explanation(
        url: str,
        risk_level: str,
        trusted_prob: float,
        phishing_prob: float,
        url_features: Dict[str, Any],
        page_features: Dict[str, Any],
        redirect_features: Dict[str, Any],
        page_available: bool = True,
        model_version: str = "CyberShield Website Security Model v1"
    ) -> Dict[str, Any]:
        """
        Synthesizes model probabilities, extracted features, and deterministic evidence rules
        into structured evidence and Explainable AI Markdown.
        """
        structured_evidence, positive_indicators, risk_indicators = generate_security_evidence(
            url_features=url_features,
            page_features=page_features,
            redirect_features=redirect_features,
            page_available=page_available
        )

        # Build list of evidence lines for the UI (✓ checks and ✗ warnings)
        display_evidence: List[str] = []
        for r in risk_indicators:
            display_evidence.append(f"✗ {r}")
        for p in positive_indicators:
            display_evidence.append(f"✓ {p}")

        if not display_evidence:
            display_evidence = ["✓ No immediate suspicious indicators detected"]

        # Build Markdown XAI Assessment
        lines = [
            "### 🛡️ Explainable AI (XAI) Assessment:",
            f"* **Estimated Classification**: {risk_level} (Estimated Phishing Risk: {phishing_prob:.1f}%, Estimated Trusted Probability: {trusted_prob:.1f}%)",
        ]

        # Model Assessment Bullet
        if risk_level in ("HIGH", "CRITICAL"):
            lines.append(f"* **Model Assessment**: Multiple high-risk signals identified across URL and page structure. Phishing probability evaluated at {phishing_prob:.1f}%.")
        elif risk_level == "MEDIUM":
            lines.append(f"* **Model Assessment**: Elevated risk indicators detected requiring caution. Phishing probability evaluated at {phishing_prob:.1f}%.")
        else:
            lines.append(f"* **Model Assessment**: Normal structural patterns with high legitimacy confidence. Trusted probability evaluated at {trusted_prob:.1f}%.")

        # Form & Data Inputs Bullet
        if page_available:
            pwd = page_features.get("has_password_field", 0) > 0
            otp = page_features.get("has_otp_field", 0) > 0
            card = page_features.get("has_payment_field", 0) > 0
            ext_form = page_features.get("has_external_form_submit", 0) > 0

            form_findings = []
            if pwd:
                form_findings.append("Password input detected")
            if otp:
                form_findings.append("OTP/2FA input detected")
            if card:
                form_findings.append("Payment card input detected")
            if ext_form:
                form_findings.append("Form submits to external domain")

            if form_findings:
                lines.append(f"* **Form & Data Inputs**: {', '.join(form_findings)}.")
            else:
                lines.append("* **Form & Data Inputs**: No credential collection or external form submissions detected.")

            # Script & DOM Bullet
            has_eval = page_features.get("has_eval", 0) > 0
            has_iframe = page_features.get("has_hidden_iframe", 0) > 0
            has_exec = page_features.get("has_executable_download", 0) > 0
            
            dom_findings = []
            if has_eval:
                dom_findings.append("Dynamic script execution (eval) present")
            if has_iframe:
                dom_findings.append("Hidden iframe embedded")
            if has_exec:
                dom_findings.append("Direct binary executable download link found")

            if dom_findings:
                lines.append(f"* **Script & Structural Telemetry**: {', '.join(dom_findings)}.")
            else:
                lines.append("* **Script & Structural Telemetry**: Clean DOM structure with no obfuscated scripts or hidden iframes.")

            # Redirects Bullet
            red_count = redirect_features.get("redirect_count", 0)
            dom_change = redirect_features.get("has_domain_change", 0) > 0
            if red_count > 0 and dom_change:
                lines.append(f"* **Navigation & Redirects**: {red_count} redirect hop(s) detected with cross-domain destination change.")
            elif red_count > 0:
                lines.append(f"* **Navigation & Redirects**: {red_count} internal redirect hop(s) detected.")
            else:
                lines.append("* **Navigation & Redirects**: Direct connection with no redirect hops.")
        else:
            lines.append("* **Webpage Telemetry**: Webpage content could not be retrieved safely; evaluation performed strictly using URL lexical and statistical metrics.")

        lines.append(f"* **Security Disclaimer**: This assessment reflects observed technical security indicators and does not guarantee complete absence or presence of malicious activity.")

        markdown_text = "\n".join(lines)

        return {
            "evidence": display_evidence,
            "structured_evidence": structured_evidence,
            "positive_indicators": positive_indicators,
            "risk_indicators": risk_indicators,
            "explanation_markdown": markdown_text,
            "model_version": model_version
        }
