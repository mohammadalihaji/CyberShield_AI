from typing import Dict, Any, Optional
import numpy as np
from sklearn.ensemble import RandomForestClassifier, HistGradientBoostingClassifier
from ml.config import RANDOM_STATE, N_ESTIMATORS
from ml.features.feature_schema import URL_FEATURE_NAMES, dict_to_vector


class URLSecurityModel:
    """
    RandomForest / Tree-based classifier operating strictly on URL-derived lexical,
    entropy, and structural features.
    """

    def __init__(
        self,
        n_estimators: int = N_ESTIMATORS,
        max_depth: Optional[int] = 20,
        random_state: int = RANDOM_STATE,
        class_weight: str = "balanced"
    ):
        self.model = RandomForestClassifier(
            n_estimators=n_estimators,
            max_depth=max_depth,
            random_state=random_state,
            class_weight=class_weight,
            n_jobs=-1
        )
        self.feature_names = URL_FEATURE_NAMES

    def fit(self, X: np.ndarray, y: np.ndarray) -> "URLSecurityModel":
        self.model.fit(X, y)
        return self

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        return self.model.predict_proba(X)

    def predict_single(self, url_features: Dict[str, Any]) -> float:
        """
        Returns estimated phishing probability for a single URL feature dictionary.
        """
        vec = dict_to_vector(url_features, self.feature_names).reshape(1, -1)
        proba = self.model.predict_proba(vec)[0]
        # Assuming class 1 is phishing, class 0 is legitimate
        if len(proba) >= 2:
            return float(proba[1])
        return float(proba[0])

    def get_feature_importances(self) -> Dict[str, float]:
        if hasattr(self.model, "feature_importances_"):
            importances = self.model.feature_importances_
            return {name: float(imp) for name, imp in zip(self.feature_names, importances)}
        return {}
