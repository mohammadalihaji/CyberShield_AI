import unittest
from ml.inference.website_analyzer import WebsiteSecurityAnalyzer
from ml.models.calibration import ProbabilityCalibrator


class TestWebsiteSecurityAnalyzer(unittest.TestCase):

    def test_analyzer_trained_inference(self):
        analyzer = WebsiteSecurityAnalyzer()
        result = analyzer.analyze("https://example.com")
        self.assertTrue(result.get("success"), f"Analysis failed: {result.get('error')}")
        self.assertIn("risk_level", result)
        self.assertIn("trusted_probability", result)
        self.assertIn("phishing_probability", result)
        self.assertIn("explanation_markdown", result)
        self.assertIn("evidence", result)
        self.assertEqual(
            result["trusted_probability"] + result["phishing_probability"],
            100.0
        )

    def test_probability_calibrator_mapping(self):
        self.assertEqual(ProbabilityCalibrator.map_risk_level(0.05), "LOW")
        self.assertEqual(ProbabilityCalibrator.map_risk_level(0.35), "MEDIUM")
        self.assertEqual(ProbabilityCalibrator.map_risk_level(0.65), "HIGH")
        self.assertEqual(ProbabilityCalibrator.map_risk_level(0.90), "CRITICAL")

    def test_probability_calibrator_format(self):
        fmt = ProbabilityCalibrator.format_probabilities(0.058)
        self.assertEqual(fmt["risk_level"], "LOW")
        self.assertEqual(fmt["phishing_probability"], 5.8)
        self.assertEqual(fmt["trusted_probability"], 94.2)
        self.assertEqual(fmt["phishing_probability"] + fmt["trusted_probability"], 100.0)


if __name__ == "__main__":
    unittest.main()
