"""Signal-quality filtering for findings emitted by pipeline stages.

The filter combines the calibrated severity model with evidence-quality
features and learned false-positive patterns. It is dependency-free, but shaped
like a tiny logistic model so it can be tuned from golden-set evaluations and
telemetry without changing every detector.
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Try importing scikit-learn gracefully
try:
    import numpy as np
    from sklearn.linear_model import LogisticRegression

    HAS_ML_LIBS = True
except ImportError:
    HAS_ML_LIBS = False
    import numpy as np

DEFAULT_REPORT_THRESHOLD = 0.50
HIGH_CONFIDENCE_FP_THRESHOLD = 0.78
MODEL_VERSION = "signal-quality-logreg-v1"


class SignalQualityMLPipeline:
    """LogisticRegression model classifier wrapper for evaluating signal qualities."""

    def __init__(self) -> None:
        # Pre-initialize coefficients to mirror the exact behavior of the arithmetic scoring
        self.coef_ = np.array(
            [
                [
                    1.65,  # confidence
                    2.35,  # model_tp
                    -1.85,  # model_fp
                    -2.25,  # fp_pattern_probability
                    0.55,  # status_changed
                    0.35,  # content_changed
                    0.35,  # redirect_changed
                    0.40,  # body_similarity_low (similarity < 0.45)
                    1.10,  # reproducible
                    0.65,  # intra_run_confirmed
                    1.35,  # cross_run_reproducible
                    1.20,  # trust_boundary_shift
                    0.45,  # correlated signals (>=2)
                    -0.50,  # low-risk endpoint
                    -0.25,  # noisy category
                ]
            ]
        )
        self.intercept_ = np.array([-0.85])
        self.classes_ = np.array([0, 1])

        self.model = None
        if HAS_ML_LIBS:
            try:
                self.model = LogisticRegression(solver="lbfgs")
                self.model.coef_ = self.coef_.copy()
                self.model.intercept_ = self.intercept_.copy()
                self.model.classes_ = self.classes_.copy()
            except Exception:
                self.model = None

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        if HAS_ML_LIBS and self.model is not None:
            try:
                return self.model.predict_proba(X)
            except Exception:
                pass

        # Elegant matrix multiplication fallback
        scores = np.dot(X, self.coef_.T) + self.intercept_
        scores = np.clip(scores, -20.0, 20.0)
        probs = 1.0 / (1.0 + np.exp(-scores))
        return np.hstack([1.0 - probs, probs])

    def fit(self, X: np.ndarray, y: np.ndarray) -> None:
        if HAS_ML_LIBS and self.model is not None:
            if len(np.unique(y)) > 1:
                try:
                    self.model.fit(X, y)
                    self.coef_ = self.model.coef_
                    self.intercept_ = self.model.intercept_
                except Exception:
                    pass


ml_pipeline = SignalQualityMLPipeline()


@dataclass(frozen=True)
class SignalQualityResult:
    """A model-style quality prediction for one finding."""

    quality_score: float
    true_positive_probability: float
    false_positive_probability: float
    action: str
    reportable: bool
    reasons: list[str] = field(default_factory=list)
    model_version: str = MODEL_VERSION

    def as_dict(self) -> dict[str, Any]:
        return {
            "quality_score": self.quality_score,
            "true_positive_probability": self.true_positive_probability,
            "false_positive_probability": self.false_positive_probability,
            "action": self.action,
            "reportable": self.reportable,
            "reasons": self.reasons,
            "model_version": self.model_version,
        }


@dataclass(frozen=True)
class GoldenSetEvaluation:
    """Summary metrics for a controlled false-positive reduction check."""

    total_findings: int
    total_real_findings: int
    baseline_false_positives: int
    filtered_false_positives: int
    baseline_fp_per_1000_real: float
    filtered_fp_per_1000_real: float
    fp_reduction: float
    true_positive_retention: float
    passed: bool

    def as_dict(self) -> dict[str, Any]:
        return {
            "total_findings": self.total_findings,
            "total_real_findings": self.total_real_findings,
            "baseline_false_positives": self.baseline_false_positives,
            "filtered_false_positives": self.filtered_false_positives,
            "baseline_fp_per_1000_real": self.baseline_fp_per_1000_real,
            "filtered_fp_per_1000_real": self.filtered_fp_per_1000_real,
            "fp_reduction": self.fp_reduction,
            "true_positive_retention": self.true_positive_retention,
            "passed": self.passed,
        }


def _clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    return max(low, min(high, value))


def _numeric(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except TypeError, ValueError:
        return default


def _sigmoid(value: float) -> float:
    if value >= 0:
        z = math.exp(-value)
        return 1.0 / (1.0 + z)
    z = math.exp(value)
    return z / (1.0 + z)


def _evidence(item: dict[str, Any]) -> dict[str, Any]:
    evidence = item.get("evidence")
    return evidence if isinstance(evidence, dict) else {}


def _diff(item: dict[str, Any]) -> dict[str, Any]:
    diff = _evidence(item).get("diff")
    return diff if isinstance(diff, dict) else {}


def _signals(item: dict[str, Any]) -> set[str]:
    evidence = _evidence(item)
    raw_signals = item.get("signals") or evidence.get("signals") or []
    if not isinstance(raw_signals, list):
        raw_signals = [raw_signals]
    combined = str(item.get("combined_signal") or "")
    tokens = {str(signal).strip().lower() for signal in raw_signals if str(signal).strip()}
    tokens.update(part.strip().lower() for part in combined.split("+") if part.strip())
    return tokens


def _body_text(item: dict[str, Any]) -> str:
    evidence = _evidence(item)
    parts = [
        evidence.get("body_snippet"),
        evidence.get("response"),
        evidence.get("match"),
        item.get("description"),
        item.get("title"),
    ]
    return " ".join(str(part) for part in parts if part).lower()


def _status_code(item: dict[str, Any]) -> int:
    evidence = _evidence(item)
    diff = _diff(item)
    return int(
        _numeric(
            item.get("response_status")
            or evidence.get("response_status")
            or diff.get("mutated_status")
            or 0
        )
    )


def _pattern_match(
    item: dict[str, Any],
    dynamic_fp_patterns: list[dict[str, Any]] | None = None,
) -> tuple[float, str]:
    status_code = _status_code(item)
    body = _body_text(item)
    patterns: list[dict[str, Any]] = []
    patterns.extend(dynamic_fp_patterns or [])
    patterns.extend(
        [
            {
                "category": "rate_limit",
                "status_code_pattern": [429, 503],
                "body_pattern": ["rate limit", "too many requests", "throttl", "slow down"],
                "fp_probability": 0.92,
            },
            {
                "category": "waf_block",
                "status_code_pattern": [403, 406, 418],
                "body_pattern": ["blocked", "waf", "cloudflare", "akamai", "access denied"],
                "fp_probability": 0.88,
            },
            {
                "category": "cdn_error",
                "status_code_pattern": [502, 503, 504, 520, 521, 522, 523, 524],
                "body_pattern": ["bad gateway", "service unavailable", "origin error"],
                "fp_probability": 0.86,
            },
            {
                "category": "generic_error",
                "status_code_pattern": [500, 501, 505],
                "body_pattern": ["internal server error", "not implemented"],
                "fp_probability": 0.70,
            },
        ]
    )

    best_probability = 0.0
    best_category = ""
    for pattern in patterns:
        raw_statuses = pattern.get("status_code_pattern", [])
        raw_bodies = pattern.get("body_pattern", [])
        if isinstance(raw_statuses, str):
            raw_statuses = json.loads(raw_statuses or "[]")
        if isinstance(raw_bodies, str):
            raw_bodies = json.loads(raw_bodies or "[]")
        statuses = {int(code) for code in raw_statuses}
        indicators = [str(indicator).lower() for indicator in raw_bodies]
        if status_code in statuses and any(indicator in body for indicator in indicators):
            probability = _numeric(pattern.get("fp_probability"), 0.75)
            if probability > best_probability:
                best_probability = probability
                best_category = str(pattern.get("category") or "dynamic")
    return best_probability, best_category


def extract_features(
    item: dict[str, Any],
    dynamic_fp_patterns: list[dict[str, Any]] | None = None,
) -> list[float]:
    """Extract a 15-dimensional numerical feature vector from a finding item."""
    evidence = _evidence(item)
    diff = _diff(item)
    signals = _signals(item)
    confidence = _clamp(_numeric(item.get("confidence", item.get("finding_confidence", 0.5)), 0.5))
    model_tp = _clamp(_numeric(item.get("true_positive_probability"), confidence))
    model_fp = _clamp(_numeric(item.get("false_positive_probability"), 1.0 - model_tp))
    fp_pattern_probability, _ = _pattern_match(item, dynamic_fp_patterns)

    return [
        confidence,
        model_tp,
        model_fp,
        fp_pattern_probability,
        1.0 if diff.get("status_changed") else 0.0,
        1.0 if diff.get("content_changed") else 0.0,
        1.0 if diff.get("redirect_changed") else 0.0,
        1.0 if _numeric(diff.get("body_similarity"), 1.0) < 0.45 else 0.0,
        1.0 if (evidence.get("reproducible") or evidence.get("confirmed")) else 0.0,
        1.0 if evidence.get("intra_run_confirmed") else 0.0,
        1.0 if evidence.get("cross_run_reproducible") else 0.0,
        1.0
        if (evidence.get("trust_boundary_shift") or evidence.get("trust_boundary") == "cross-host")
        else 0.0,
        1.0 if len(signals) >= 2 else 0.0,
        1.0
        if str(item.get("endpoint_type", "")).upper() in {"STATIC", "ASSET", "DOCUMENTATION"}
        else 0.0,
        1.0
        if str(item.get("category", "")).lower() in {"anomaly", "misconfiguration", "exposure"}
        else 0.0,
    ]


def score_signal_quality(
    item: dict[str, Any],
    dynamic_fp_patterns: list[dict[str, Any]] | None = None,
    *,
    report_threshold: float = DEFAULT_REPORT_THRESHOLD,
    weights: dict[str, float] | None = None,
) -> SignalQualityResult:
    """Predict whether a finding should stay in analyst triage using a fitted LogisticRegression model."""

    evidence = _evidence(item)
    diff = _diff(item)
    signals = _signals(item)
    fp_pattern_probability, fp_category = _pattern_match(item, dynamic_fp_patterns)
    reasons: list[str] = []

    if fp_pattern_probability:
        reasons.append(f"matches {fp_category} FP pattern")

    if diff.get("status_changed"):
        reasons.append("status changed")
    if diff.get("content_changed"):
        reasons.append("content changed")
    if diff.get("redirect_changed"):
        reasons.append("redirect changed")
    if _numeric(diff.get("body_similarity"), 1.0) < 0.45:
        reasons.append("response body materially changed")
    if evidence.get("reproducible") or evidence.get("confirmed"):
        reasons.append("reproducible")
    if evidence.get("intra_run_confirmed"):
        reasons.append("confirmed in run")
    if evidence.get("cross_run_reproducible"):
        reasons.append("confirmed across runs")
    if evidence.get("trust_boundary_shift") or evidence.get("trust_boundary") == "cross-host":
        reasons.append("trust boundary crossed")
    if len(signals) >= 2:
        reasons.append("correlated signals")
    if str(item.get("endpoint_type", "")).upper() in {"STATIC", "ASSET", "DOCUMENTATION"}:
        reasons.append("low-risk endpoint type")
    if str(item.get("category", "")).lower() in {"anomaly", "misconfiguration", "exposure"}:
        reasons.append("historically noisy category")

    # Evaluate using ML pipeline
    features = extract_features(item, dynamic_fp_patterns)
    if weights:
        coef = ml_pipeline.coef_.copy()
        if "confidence" in weights:
            coef[0, 0] = weights["confidence"]
        if "model_tp" in weights:
            coef[0, 1] = weights["model_tp"]
        if "model_fp" in weights:
            coef[0, 2] = weights["model_fp"]
        if "fp_pattern_probability" in weights:
            coef[0, 3] = weights["fp_pattern_probability"]
        if "reproducible" in weights:
            coef[0, 8] = weights["reproducible"]

        X = np.array([features])
        scores = np.dot(X, coef.T) + ml_pipeline.intercept_
        scores = np.clip(scores, -20.0, 20.0)
        tp_prob = 1.0 / (1.0 + np.exp(-scores))
        tp_probability = _clamp(float(tp_prob[0, 0]))
        fp_probability = _clamp(float(1.0 - tp_probability))
    else:
        probs = ml_pipeline.predict_proba(np.array([features]))[0]
        tp_probability = _clamp(float(probs[1]))
        fp_probability = _clamp(float(probs[0]))

    if fp_pattern_probability >= HIGH_CONFIDENCE_FP_THRESHOLD and not (
        evidence.get("reproducible")
        or evidence.get("confirmed")
        or evidence.get("cross_run_reproducible")
        or evidence.get("trust_boundary_shift")
    ):
        action = "suppress"
        reportable = False
    elif tp_probability >= report_threshold:
        action = "keep"
        reportable = True
    elif tp_probability >= report_threshold - 0.12:
        action = "triage_low_priority"
        reportable = True
    else:
        action = "suppress"
        reportable = False

    if action == "suppress":
        try:
            from src.infrastructure.observability.metrics import get_metrics

            get_metrics().counter("fp_reduction_total").inc()
        except Exception:
            pass

    return SignalQualityResult(
        quality_score=round(tp_probability * 100.0, 2),
        true_positive_probability=round(tp_probability, 4),
        false_positive_probability=round(fp_probability, 4),
        action=action,
        reportable=reportable,
        reasons=reasons[:8],
    )


def annotate_signal_quality(
    findings: list[dict[str, Any]],
    dynamic_fp_patterns: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Attach signal-quality metadata to findings."""

    annotated: list[dict[str, Any]] = []
    for finding in findings:
        result = score_signal_quality(finding, dynamic_fp_patterns)
        annotated.append(
            {
                **finding,
                "signal_quality": result.as_dict(),
                "signal_quality_score": result.quality_score,
                "false_positive_probability": result.false_positive_probability,
                "true_positive_probability": result.true_positive_probability,
                "reportable": result.reportable,
            }
        )
    return annotated


def evaluate_golden_set(
    fixture_path: str | Path,
    *,
    required_reduction: float = 0.50,
    min_tp_retention: float = 0.90,
) -> GoldenSetEvaluation:
    """Evaluate FP reduction on a labeled golden set stored in tests/fixtures."""

    payload = json.loads(Path(fixture_path).read_text(encoding="utf-8"))
    records = payload.get("findings", payload)
    total = len(records)
    real = [record for record in records if record.get("label") == "true_positive"]
    false = [record for record in records if record.get("label") == "false_positive"]
    kept = [record for record in records if score_signal_quality(record["finding"]).reportable]
    kept_false = [record for record in kept if record.get("label") == "false_positive"]
    kept_real = [record for record in kept if record.get("label") == "true_positive"]
    real_count = max(1, len(real))
    baseline_fp_per_1000 = round(len(false) / real_count * 1000.0, 2)
    filtered_fp_per_1000 = round(len(kept_false) / real_count * 1000.0, 2)
    reduction = 1.0
    if baseline_fp_per_1000 > 0:
        reduction = 1.0 - (filtered_fp_per_1000 / baseline_fp_per_1000)
    tp_retention = len(kept_real) / real_count
    return GoldenSetEvaluation(
        total_findings=total,
        total_real_findings=len(real),
        baseline_false_positives=len(false),
        filtered_false_positives=len(kept_false),
        baseline_fp_per_1000_real=baseline_fp_per_1000,
        filtered_fp_per_1000_real=filtered_fp_per_1000,
        fp_reduction=round(reduction, 4),
        true_positive_retention=round(tp_retention, 4),
        passed=reduction >= required_reduction and tp_retention >= min_tp_retention,
    )


__all__ = [
    "GoldenSetEvaluation",
    "SignalQualityResult",
    "annotate_signal_quality",
    "evaluate_golden_set",
    "score_signal_quality",
]
