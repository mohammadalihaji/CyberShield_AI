import unittest
from ml.inference.safe_fetcher import SafeWebpageFetcher, is_ip_disallowed, validate_hostname_safe, SSRFSecurityException


class TestSafeWebpageFetcher(unittest.TestCase):

    def test_ip_disallowed_rules(self):
        # Loopback
        self.assertTrue(is_ip_disallowed("127.0.0.1"))
        self.assertTrue(is_ip_disallowed("127.0.0.5"))
        self.assertTrue(is_ip_disallowed("::1"))

        # Private IP ranges
        self.assertTrue(is_ip_disallowed("10.0.0.1"))
        self.assertTrue(is_ip_disallowed("172.16.0.1"))
        self.assertTrue(is_ip_disallowed("192.168.1.1"))

        # Cloud metadata
        self.assertTrue(is_ip_disallowed("169.254.169.254"))

        # Public IPs
        self.assertFalse(is_ip_disallowed("8.8.8.8"))
        self.assertFalse(is_ip_disallowed("1.1.1.1"))

    def test_ssrf_blocked_hostnames(self):
        with self.assertRaises(SSRFSecurityException):
            validate_hostname_safe("localhost")

        with self.assertRaises(SSRFSecurityException):
            validate_hostname_safe("127.0.0.1")

        with self.assertRaises(SSRFSecurityException):
            validate_hostname_safe("169.254.169.254")

    def test_fetcher_blocks_private_ip(self):
        fetcher = SafeWebpageFetcher()
        result = fetcher.fetch("http://127.0.0.1:8080/secret")
        self.assertFalse(result.success)
        self.assertIn("Security Policy", str(result.error))

    def test_fetcher_blocks_disallowed_scheme(self):
        fetcher = SafeWebpageFetcher()
        result = fetcher.fetch("file:///etc/passwd")
        self.assertFalse(result.success)
        self.assertIn("Disallowed scheme", str(result.error))

    def test_fetcher_blocks_javascript_scheme(self):
        fetcher = SafeWebpageFetcher()
        result = fetcher.fetch("javascript:alert(1)")
        self.assertFalse(result.success)


if __name__ == "__main__":
    unittest.main()
