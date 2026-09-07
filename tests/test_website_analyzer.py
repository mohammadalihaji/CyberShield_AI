import unittest
from ml.inference.website_analyzer import WebsiteSecurityAnalyzer
from ml.models.calibration import ProbabilityCalibrator


class TestWebsiteSecurityAnalyzer(unittest.TestCase):

    def test_analyzer_pre_training_status(self):
        analyzer = WebsiteSecurityAnalyzer()
        result = analyzer.analyze("https://example.com")
        # Prior to CompPhish V4 training, the analyzer should return MODEL_NOT_READY
        self.assertIn("status", result)
        self.assertEqual(result["status"], "MODEL_NOT_READY")
        self.assertFalse(result["success"])
        self.assertIn("CompPhish V4", result["error"])
        self.assertTrue("explanation_markdown" in result)

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
