"""XGBoost and scikit-learn severity estimation classifier with tabular fallback."""

from __future__ import annotations

import logging
from typing import Any
import numpy as np

logger = logging.getLogger(__name__)

# Try importing XGBoost and scikit-learn gracefully
try:
    import xgboost as xgb
    from sklearn.feature_extraction import FeatureHasher
    from sklearn.linear_model import LogisticRegression
    HAS_ML_LIBS = True
except ImportError:
    HAS_ML_LIBS = False
    logger.warning(
        "ML Libraries (xgboost, scikit-learn) could not be loaded. Running on fallback model mode."
    )

from src.intelligence.ml.feature_vector import FeatureVector


class XGBoostSeverityPipeline:
    """Wrapper that manages feature vectorization and XGBoost/scikit-learn training."""

    def __init__(self, *, n_features: int = 128) -> None:
        self.n_features = n_features
        self.hasher = None
        self.model = None
        self.is_trained = False
        
        if HAS_ML_LIBS:
            self.hasher = FeatureHasher(n_features=self.n_features, input_type="pair")
            # Set up XGBoost Classifier with max depth to prevent overfitting on security metrics
            try:
                self.model = xgb.XGBClassifier(
                    max_depth=3,
                    n_estimators=30,
                    learning_rate=0.15,
                    objective="binary:logistic",
                    eval_metric="logloss",
                    random_state=42,
                )
            except Exception as e:
                logger.warning("Could not initialize XGBoost Classifier: %s. Using LogisticRegression instead.", e)
                self.model = LogisticRegression(C=1.0, penalty="l2", solver="lbfgs", random_state=42)

    def _vectorize(self, vectors: list[FeatureVector]) -> np.ndarray:
        """Transform high-dimensional sparse tokens and numerical features into dense NumPy arrays."""
        if not HAS_ML_LIBS or self.hasher is None:
            raise RuntimeError("ML Vectorization failed: xgboost or scikit-learn is not available.")

        # Vectorize categorical tokens using hashing trick to maintain memory boundary
        token_pairs = [[(t, 1.0) for t in vec.tokens] for vec in vectors]
        sparse_tokens = self.hasher.transform(token_pairs).toarray()

        # Compile numeric tabular arrays
        numeric = np.array([
            [
                vec.confidence,
                vec.legacy_impact,
                vec.cvss,
                vec.score_hint,
                vec.response_delta,
                vec.diff_score,
                vec.status_changed,
                vec.content_changed,
                vec.redirect_changed,
                vec.reproducible,
            ]
            for vec in vectors
        ], dtype=np.float32)

        return np.hstack([numeric, sparse_tokens])

    def fit(self, findings: list[dict[str, Any]], labels: list[float]) -> bool:
        """Fit the classifier model using validated historical security outcomes."""
        if not HAS_ML_LIBS or self.model is None or not findings:
            return False

        try:
            vectors = [FeatureVector.from_finding(f) for f in findings]
            X = self._vectorize(vectors)
            y = np.array(labels, dtype=np.float32)

            # Fit the underlying estimator
            if hasattr(self.model, "fit"):
                self.model.fit(X, y)
                self.is_trained = True
                logger.info("XGBoostSeverityPipeline: Successfully fitted model on %d samples.", len(findings))
                return True
        except Exception as e:
            logger.error("XGBoostSeverityPipeline: Failed to fit model: %s", e)
            self.is_trained = False

        return False

    def predict_probability(self, finding: dict[str, Any]) -> float:
        """Estimate the probability of a finding being a True Positive (TP)."""
        if not HAS_ML_LIBS or self.model is None or not self.is_trained:
            # High-fidelity baseline fallback using hand-rolled logistic coefficients
            return self._fallback_inference(finding)

        try:
            vec = FeatureVector.from_finding(finding)
            X = self._vectorize([vec])
            if hasattr(self.model, "predict_proba"):
                probs = self.model.predict_proba(X)
                return float(probs[0][1])
        except Exception as e:
            logger.warning("ML Inference error: %s. Falling back to default sigmoid coefficients.", e)

        return self._fallback_inference(finding)

    def _fallback_inference(self, finding: dict[str, Any]) -> float:
        """Pure NumPy fallback algorithm to maintain functionality if compilation fails."""
        vec = FeatureVector.from_finding(finding)
        feats = vec.to_features_dict()
        
        # Exact default weights from calibrated hand-rolled logreg model
        default_weights = {
            "bias": -0.85,
            "confidence": 1.35,
            "legacy_impact": 1.0,
            "reproducible": 1.1,
            "cvss": 0.5,
            "diff_score": 0.8,
        }
        
        feature_sum = sum(default_weights.get(k, 0.0) * v for k, v in feats.items())
        
        # Clean Sigmoid implementation
        if feature_sum >= 0:
            return 1.0 / (1.0 + np.exp(-feature_sum))
        z = np.exp(feature_sum)
        return z / (1.0 + z)
