import unittest
from ml.features.url_features import extract_url_features, extract_base_domain, calculate_entropy


class TestURLFeatureExtraction(unittest.TestCase):

    def test_normal_url(self):
        url = "https://www.google.com/search?q=cybersecurity"
        feats = extract_url_features(url)
        self.assertEqual(feats["is_https"], 1)
        self.assertEqual(feats["is_ip_address"], 0)
        self.assertEqual(feats["base_domain"], "google.com")
        self.assertGreater(feats["url_length"], 0)
        self.assertGreater(feats["hostname_length"], 0)

    def test_ip_address_hostname(self):
        url = "http://192.168.1.100/admin/login.php"
        feats = extract_url_features(url)
        self.assertEqual(feats["is_ip_address"], 1)
        self.assertEqual(feats["is_https"], 0)
        self.assertIn("login", url)
        self.assertGreater(feats["suspicious_keywords_count"], 0)

    def test_at_symbol_in_url(self):
        url = "https://legitimate-site.com@attacker-site.com/login"
        feats = extract_url_features(url)
        self.assertEqual(feats["has_at_symbol"], 1)

    def test_brand_in_subdomain_mismatch(self):
        url = "https://paypal.com.account-verification-service.top/login"
        feats = extract_url_features(url)
        self.assertEqual(feats["suspicious_tld_indicator"], 1)
        self.assertEqual(feats["brand_in_subdomain_or_path"], 1)
        self.assertEqual(feats["base_domain"], "account-verification-service.top")

    def test_punycode(self):
        url = "https://xn--pple-43d.com/login"
        feats = extract_url_features(url)
        self.assertEqual(feats["is_punycode"], 1)

    def test_entropy_calculation(self):
        low_ent = calculate_entropy("aaaaaaa")
        high_ent = calculate_entropy("a8!d7@Z#9$kL")
        self.assertLess(low_ent, high_ent)


if __name__ == "__main__":
    unittest.main()
