"""SHAP Explainability Engine - Feature Contribution Calculator for Severity Model."""

from __future__ import annotations

import logging
from typing import Any

import numpy as np

from src.intelligence.ml.feature_vector import FeatureVector
from src.intelligence.ml.xgboost_pipeline import XGBoostSeverityPipeline

logger = logging.getLogger(__name__)


class SHAPExplainer:
    """
    Computes local feature contributions (SHAP-like values) for finding severity assessments.
    Enables transparency and auditability on the security cockpit.
    """

    def __init__(self, pipeline: XGBoostSeverityPipeline | None = None) -> None:
        self.pipeline = pipeline or XGBoostSeverityPipeline()

    def explain(self, finding: dict[str, Any]) -> dict[str, Any]:
        """
        Decompose a finding's severity score into individual feature contributions.
        Returns a structured dictionary of SHAP log-odds and probability-scale impacts.
        """
        vec = FeatureVector.from_finding(finding)
        feats = vec.to_features_dict()

        # Retrieve weights and bias from model or fallback
        weights = {}
        bias = -0.85

        is_fallback = True
        model = self.pipeline.model if hasattr(self.pipeline, "model") else None

        # 1. Extract parameters from fitted model if available
        if hasattr(self.pipeline, "is_trained") and self.pipeline.is_trained and model is not None:
            try:
                # If scikit-learn LogisticRegression
                if hasattr(model, "coef_") and hasattr(model, "intercept_"):
                    coef = model.coef_[0]
                    intercept = float(model.intercept_[0])
                    bias = intercept

                    # Categorical Feature Hasher features map to vector columns
                    # Numerical features are mapped in vector order
                    num_keys = [
                        "confidence",
                        "legacy_impact",
                        "cvss",
                        "score_hint",
                        "response_delta",
                        "diff_score",
                        "status_changed",
                        "content_changed",
                        "redirect_changed",
                        "reproducible",
                    ]
                    for idx, key in enumerate(num_keys):
                        weights[key] = float(coef[idx])

                    # Categorical tokens are hashed into columns starting at index 10
                    # For simplicity, we approximate token contributions from coefs of active slots
                    token_pairs = [[(t, 1.0) for t in vec.tokens]]
                    if self.pipeline.hasher is not None:
                        sparse_cols = self.pipeline.hasher.transform(token_pairs).toarray()[0]
                        for idx, val in enumerate(sparse_cols):
                            if val != 0.0:
                                slot_idx = 10 + idx
                                if slot_idx < len(coef):
                                    # Aggregate all active tokens into a generic token weight
                                    weights["token_categorizations"] = (
                                        weights.get("token_categorizations", 0.0)
                                        + float(coef[slot_idx]) * val
                                    )
                    is_fallback = False
                # If XGBoost Classifier, calculate gain-based feature contributions
                elif hasattr(model, "feature_importances_"):
                    # Approximate local contributions using feature importances as weights
                    importances = model.feature_importances_
                    bias = -0.5
                    num_keys = [
                        "confidence",
                        "legacy_impact",
                        "cvss",
                        "score_hint",
                        "response_delta",
                        "diff_score",
                        "status_changed",
                        "content_changed",
                        "redirect_changed",
                        "reproducible",
                    ]
                    for idx, key in enumerate(num_keys):
                        if idx < len(importances):
                            weights[key] = float(importances[idx]) * 3.5  # scale factor
                    is_fallback = False
            except Exception as e:
                logger.warning(
                    "Failed to extract SHAP weights from trained model: %s. Using fallback weights.",
                    e,
                )

        # 2. Revert to fallback default calibrated logreg weights
        if is_fallback:
            weights = {
                "confidence": 1.35,
                "legacy_impact": 1.0,
                "reproducible": 1.1,
                "cvss": 0.5,
                "diff_score": 0.8,
            }
            bias = -0.85

        # Compute log-odds (logit) contributions: C_i = w_i * x_i
        logit_contributions = {}
        total_logit = bias

        for key, value in feats.items():
            # Check numerical weight
            weight_key = key
            if key.startswith("token:"):
                # Group hashed tokens under tokens weight
                weight_key = "token_categorizations"

            w = weights.get(weight_key, 0.0)
            c = w * value
            if c != 0.0:
                logit_contributions[key] = round(c, 4)
                total_logit += c

        # Sigmoid math
        def sigmoid(z: float) -> float:
            if z >= 0:
                return float(1.0 / (1.0 + np.exp(-z)))
            val = np.exp(z)
            return float(val / (1.0 + val))

        final_prob = sigmoid(total_logit)

        # Calculate marginal probability impact for each contributor
        feature_impacts: list[dict[str, Any]] = []
        for key, logit_c in logit_contributions.items():
            # Probability without this feature's contribution
            prob_without = sigmoid(total_logit - logit_c)
            prob_delta = final_prob - prob_without

            sign = "+" if prob_delta >= 0 else ""
            desc = f"{sign}{prob_delta * 100:.1f}% severity impact"

            clean_name = key.replace("token:", "token_").replace("_", " ").title()

            feature_impacts.append(
                {
                    "feature": key,
                    "label": clean_name,
                    "value": float(feats.get(key, 1.0)),
                    "logit_contribution": logit_c,
                    "probability_impact": round(prob_delta, 4),
                    "description": desc,
                }
            )

        # Sort feature impacts by magnitude of contribution
        feature_impacts.sort(key=lambda x: abs(float(x["logit_contribution"])), reverse=True)

        # Generate human-readable diagnostics summary
        positive_influences = [
            str(f.get("label", ""))
            for f in feature_impacts
            if float(f.get("logit_contribution", 0.0)) > 0.1
        ][:3]
        negative_influences = [
            str(f.get("label", ""))
            for f in feature_impacts
            if float(f.get("logit_contribution", 0.0)) < -0.1
        ][:2]

        summary_parts = []
        if positive_influences:
            summary_parts.append(f"Severity is highly driven by: {', '.join(positive_influences)}.")
        if negative_influences:
            summary_parts.append(
                f"Auto-suppressive metrics include: {', '.join(negative_influences)}."
            )
        if not summary_parts:
            summary_parts.append("Severity score aligns with the global prior baseline.")

        diagnostic_summary = " ".join(summary_parts)

        return {
            "finding_id": finding.get("id") or finding.get("finding_id", "unknown"),
            "severity_score": round(final_prob * 10.0, 2),  # 0.0 - 10.0 scale
            "severity_percentage": round(final_prob * 100.0, 1),
            "base_value_logit": bias,
            "base_value_prob": round(sigmoid(bias), 4),
            "final_logit": round(total_logit, 4),
            "is_fallback_model": is_fallback,
            "contributions": feature_impacts,
            "diagnostic_summary": diagnostic_summary,
        }
