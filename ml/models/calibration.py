from typing import Tuple, Dict, Any
import numpy as np
from sklearn.calibration import CalibratedClassifierCV
from ml.config import RISK_THRESHOLDS


class ProbabilityCalibrator:
    """
    Applies probability calibration and translates calibrated scores into
    Trusted / Phishing probabilities and categorical Risk Levels.
    """

    @staticmethod
    def calibrate_classifier(base_estimator: Any, X_val: np.ndarray, y_val: np.ndarray, method: str = "isotonic") -> CalibratedClassifierCV:
        """
        Fits a CalibratedClassifierCV on validation data using prefit base estimator.
        """
        calibrated = CalibratedClassifierCV(estimator=base_estimator, method=method, cv="prefit")
        calibrated.fit(X_val, y_val)
        return calibrated

    @staticmethod
    def map_risk_level(phishing_prob: float) -> str:
        """
        Maps a calibrated phishing probability (0.0 to 1.0) to a standardized Risk Level:
        - 0.00 to 0.20: LOW
        - 0.20 to 0.50: MEDIUM
        - 0.50 to 0.75: HIGH
        - 0.75 to 1.00: CRITICAL
        """
        if phishing_prob < RISK_THRESHOLDS["LOW"]:
            return "LOW"
        elif phishing_prob < RISK_THRESHOLDS["MEDIUM"]:
            return "MEDIUM"
        elif phishing_prob < RISK_THRESHOLDS["HIGH"]:
            return "HIGH"
        else:
            return "CRITICAL"

    @staticmethod
    def format_probabilities(phishing_prob: float) -> Dict[str, Any]:
        """
        Formats probabilities ensuring P(legitimate) + P(phishing) = 100.0%.
        """
        clamped_phish = max(0.0, min(1.0, float(phishing_prob)))
        phish_pct = round(clamped_phish * 100.0, 1)
        trust_pct = round((1.0 - clamped_phish) * 100.0, 1)

        # Ensure exact 100% sum
        if phish_pct + trust_pct != 100.0:
            trust_pct = round(100.0 - phish_pct, 1)

        risk_level = ProbabilityCalibrator.map_risk_level(clamped_phish)

        return {
            "risk_level": risk_level,
            "phishing_probability": phish_pct,
            "trusted_probability": trust_pct,
            "phishing_score": phish_pct,
            "raw_phishing_prob": clamped_phish
        }
