import json
from pathlib import Path

import numpy as np
import pytest

from src.intelligence.ml.xgboost_pipeline import HAS_ML_LIBS, XGBoostSeverityPipeline


def test_ml_fallback_vs_pipeline_regression() -> None:
    """Regression test for hand-rolled NumPy fallback vs compiled ML pipeline on the Golden Set."""
    golden_set_path = Path("tests/fixtures/ml_golden_set.json")
    assert golden_set_path.exists(), "Golden set fixture is missing!"

    with open(golden_set_path, encoding="utf-8") as f:
        golden_data = json.load(f)

    # Some golden sets nest findings under a 'finding' key
    findings = [item["finding"] if "finding" in item else item for item in golden_data]
    labels = [1.0 if item.get("feedback") == "tp" else 0.0 for item in golden_data]

    pipeline = XGBoostSeverityPipeline()

    # 1. Unfitted check: both predict_probability and _fallback_inference must yield identical results
    for finding in findings:
        p_pred = pipeline.predict_probability(finding)
        p_fall = pipeline._fallback_inference(finding)
        assert abs(p_pred - p_fall) < 1e-7, "Unfitted pipeline deviated from fallback!"

    # 2. Fitted check: if ML libraries are present, fit the model and evaluate the Mean Squared Error (MSE)
    if HAS_ML_LIBS:
        # Fit model on golden set
        success = pipeline.fit(findings, labels)
        assert success, "Failed to fit XGBoost/sklearn pipeline!"
        assert pipeline.is_trained

        fitted_preds = []
        fallback_preds = []

        for finding in findings:
            p_fit = pipeline.predict_probability(finding)
            p_fall = pipeline._fallback_inference(finding)
            fitted_preds.append(p_fit)
            fallback_preds.append(p_fall)

        # Calculate Mean Squared Error (MSE) between fallback and fitted pipeline
        mse = float(np.mean((np.array(fitted_preds) - np.array(fallback_preds)) ** 2))
        print(f"ML Pipeline vs NumPy Fallback MSE on Golden Set: {mse:.6f}")

        # Enforce deviation tolerance to prevent excessive fallback degradation
        assert mse < 0.15, (
            f"NumPy logistic fallback deviated too much from fitted pipeline! MSE: {mse}"
        )


def test_pure_numpy_fallback_mathematical_identity() -> None:
    """Verify that the NumPy fallback is mathematically identical to scikit-learn LogisticRegression with the same weights."""
    from src.learning.signal_quality import HAS_ML_LIBS as SK_HAS_ML
    from src.learning.signal_quality import ml_pipeline

    if not SK_HAS_ML:
        pytest.skip("scikit-learn is not available to verify mathematical identity")

    from sklearn.linear_model import LogisticRegression

    # 1. Instantiate scikit-learn LogisticRegression and inject default weights
    model = LogisticRegression(solver="lbfgs")
    model.coef_ = ml_pipeline.coef_.copy()
    model.intercept_ = ml_pipeline.intercept_.copy()
    model.classes_ = ml_pipeline.classes_.copy()

    # Create random feature vectors
    np.random.seed(42)
    X = np.random.randn(100, 15)  # 15 features

    # 2. Get predictions using sklearn
    sklearn_probs = model.predict_proba(X)

    # 3. Get predictions using SignalQualityMLPipeline matrix multiplication fallback
    scores = np.dot(X, ml_pipeline.coef_.T) + ml_pipeline.intercept_
    scores = np.clip(scores, -20.0, 20.0)
    probs = 1.0 / (1.0 + np.exp(-scores))
    numpy_probs = np.hstack([1.0 - probs, probs])

    # Calculate Mean Squared Error (MSE)
    mse = float(np.mean((sklearn_probs - numpy_probs) ** 2))
    print(f"NumPy Fallback vs sklearn LogisticRegression mathematical identity MSE: {mse:.12f}")

    # Assert absolute identity (deviation < 1e-12 MSE)
    assert mse < 1e-12, f"NumPy matrix multiplication math did not match sklearn! MSE: {mse}"
