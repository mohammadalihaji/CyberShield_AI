from typing import Dict, Any, Optional
import numpy as np
from ml.models.calibration import ProbabilityCalibrator


class EnsembleSecurityModel:
    """
    Combines predictions from URL model, Page model, and deterministic high-severity
    security signals (e.g. credential fields submitting to external domains).
    """

    def __init__(
        self,
        url_weight: float = 0.45,
        page_weight: float = 0.55,
        calibrator: Optional[Any] = None
    ):
        self.url_weight = url_weight
        self.page_weight = page_weight
        self.calibrator = calibrator

    def predict_combined(
        self,
        url_prob: float,
        page_prob: Optional[float],
        url_features: Dict[str, Any],
        page_features: Dict[str, Any],
        redirect_features: Dict[str, Any],
        page_available: bool = True
    ) -> Dict[str, Any]:
        """
        Combines probabilities and returns calibrated risk evaluation.
        """
        if not page_available or page_prob is None:
            # Fallback to URL-only probability
            raw_prob = url_prob
        else:
            # Weighted combination of URL and Page models
            raw_prob = (self.url_weight * url_prob) + (self.page_weight * page_prob)

        # High-severity signal adjustment:
        # Example: Credential harvesting signal (password field + external form submission)
        if page_available:
            has_pwd = page_features.get("has_password_field", 0) > 0
            has_otp = page_features.get("has_otp_field", 0) > 0
            has_payment = page_features.get("has_payment_field", 0) > 0
            has_ext_form = page_features.get("has_external_form_submit", 0) > 0

            if (has_pwd or has_otp or has_payment) and has_ext_form:
                # Strong signal of credential harvesting destination mismatch
                raw_prob = max(raw_prob, 0.85)

        # Apply calibrator if available
        if self.calibrator is not None:
            try:
                # Assuming calibrator expects 2D array of raw probabilities
                calibrated_arr = self.calibrator.predict_proba(np.array([[raw_prob]]))
                if calibrated_arr.shape[1] >= 2:
                    final_phish_prob = float(calibrated_arr[0][1])
                else:
                    final_phish_prob = float(calibrated_arr[0][0])
            except Exception:
                final_phish_prob = raw_prob
        else:
            final_phish_prob = raw_prob

        # Format standardized probabilities
        result = ProbabilityCalibrator.format_probabilities(final_phish_prob)
        return result
