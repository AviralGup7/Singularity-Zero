"""XGBoost and scikit-learn severity estimation classifier with tabular fallback."""

from __future__ import annotations

import logging
from typing import Any

import numpy as np

from src.intelligence.ml.feature_vector import FeatureVector

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
                logger.warning(
                    "Could not initialize XGBoost Classifier: %s. Using LogisticRegression instead.",
                    e,
                )
                self.model = LogisticRegression(
                    C=1.0, penalty="l2", solver="lbfgs", random_state=42
                )

    def _vectorize(self, vectors: list[FeatureVector]) -> np.ndarray:
        """Transform high-dimensional sparse tokens and numerical features into dense NumPy arrays."""
        if not HAS_ML_LIBS or self.hasher is None:
            raise RuntimeError("ML Vectorization failed: xgboost or scikit-learn is not available.")

        # Vectorize categorical tokens using hashing trick to maintain memory boundary
        token_pairs = [[(t, 1.0) for t in vec.tokens] for vec in vectors]
        sparse_tokens = self.hasher.transform(token_pairs).toarray()

        # Compile numeric tabular arrays
        numeric = np.array(
            [
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
            ],
            dtype=np.float32,
        )

        return np.hstack([numeric, sparse_tokens])

    def fit(
        self,
        findings: list[dict[str, Any]],
        labels: list[float],
        sample_weights: list[float] | None = None,
    ) -> bool:
        """Fit the classifier model using validated historical security outcomes.

        ``sample_weights`` lets the caller up-weight analyst-labelled
        examples relative to automated ones so the trained model is
        more representative of human-reviewed ground truth. The
        argument is optional and falls back to uniform weights when
        omitted.
        """
        if not HAS_ML_LIBS or self.model is None or not findings:
            return False

        try:
            vectors = [FeatureVector.from_finding(f) for f in findings]
            x = self._vectorize(vectors)
            y = np.array(labels, dtype=np.float32)

            if sample_weights is None:
                weights = np.ones(len(labels), dtype=np.float32)
            else:
                weights = np.array(sample_weights, dtype=np.float32)
                if len(weights) != len(labels):
                    raise ValueError("sample_weights length must match labels length")

            fit_kwargs: dict[str, Any] = {}
            try:
                # scikit-learn / xgboost both accept ``sample_weight``.
                fit_kwargs["sample_weight"] = weights
            except Exception:  # noqa: BLE001, S110
                pass

            if hasattr(self.model, "fit"):
                try:
                    self.model.fit(x, y, **fit_kwargs)
                except TypeError:
                    # Some estimators don't accept sample_weight
                    # (e.g. when running on a stripped-down build).
                    # Fall back to an unweighted fit so the model is
                    # still updated.
                    self.model.fit(x, y)
                self.is_trained = True
                logger.info(
                    "XGBoostSeverityPipeline: Successfully fitted model on %d samples (weighted=%s).",
                    len(findings),
                    sample_weights is not None,
                )
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
            x = self._vectorize([vec])
            if hasattr(self.model, "predict_proba"):
                probs = self.model.predict_proba(x)
                return float(probs[0][1])
        except Exception as e:
            logger.warning(
                "ML Inference error: %s. Falling back to default sigmoid coefficients.", e
            )

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
            return float(1.0 / (1.0 + np.exp(-feature_sum)))
        z = np.exp(feature_sum)
        return float(z / (1.0 + z))
