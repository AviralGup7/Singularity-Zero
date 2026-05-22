"""Calibrated ML severity scoring for security findings.

The model is intentionally small and dependency-free: it trains a logistic
regression classifier over hashed finding features from the telemetry database,
then calibrates the resulting probability with beta-smoothed historical
true-positive and false-positive rates. This gives every finding a severity
score derived from observed outcomes while keeping inference cheap enough for
recon and reporting paths.
"""

from __future__ import annotations

import json
import math
import os
import sqlite3
import time
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any, cast
from urllib.parse import urlparse

from src.intelligence.ml import ModelVersion, ModelVersionRegistry, XGBoostSeverityPipeline

SEVERITY_LABELS = ("info", "low", "medium", "high", "critical")
SEVERITY_TO_IMPACT = {
    "info": 0.10,
    "low": 0.28,
    "medium": 0.52,
    "high": 0.78,
    "critical": 1.00,
}
SCORE_THRESHOLDS = (
    (8.8, "critical"),
    (6.8, "high"),
    (3.8, "medium"),
    (1.5, "low"),
    (0.0, "info"),
)
DEFAULT_DB_PATH = Path(".pipeline") / "telemetry.db"
MODEL_VERSION = "severity-logreg-v1"


@dataclass(frozen=True)
class SeverityPrediction:
    """A calibrated model severity prediction."""

    score: float
    severity: str
    true_positive_probability: float
    false_positive_probability: float
    confidence: float
    model_version: str
    training_samples: int
    calibration: dict[str, float]
    top_features: list[str] = field(default_factory=list)

    def as_metadata(self) -> dict[str, Any]:
        return {
            "model_version": self.model_version,
            "training_samples": self.training_samples,
            "true_positive_probability": self.true_positive_probability,
            "false_positive_probability": self.false_positive_probability,
            "calibration": self.calibration,
            "top_features": self.top_features,
        }


@dataclass
class _TrainingExample:
    finding: dict[str, Any]
    label: float
    weight: float


def _clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    return max(low, min(high, value))


def severity_from_score(score: float) -> str:
    """Map a 0-10 model score to a severity label."""
    for threshold, label in SCORE_THRESHOLDS:
        if score >= threshold:
            return label
    return "info"


def score_from_severity(severity: object) -> float:
    """Return the impact prior for a legacy/input severity label."""
    return SEVERITY_TO_IMPACT.get(str(severity or "info").strip().lower(), 0.35) * 10.0


def _numeric(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _normalise_token(value: object) -> str:
    return str(value or "").strip().lower().replace(" ", "_") or "unknown"


def _tokens_from_finding(finding: dict[str, Any]) -> list[str]:
    evidence = (
        cast(dict[str, Any], finding.get("evidence"))
        if isinstance(finding.get("evidence"), dict)
        else {}
    )
    signals = finding.get("signals") or evidence.get("signals") or []
    if not isinstance(signals, list):
        signals = [signals]
    url = str(finding.get("url") or finding.get("target_endpoint") or "")
    parsed = urlparse(url)
    path_parts = [part for part in parsed.path.lower().split("/") if part][:4]
    tokens = [
        f"category={_normalise_token(finding.get('category') or finding.get('finding_category'))}",
        f"plugin={_normalise_token(finding.get('plugin_name') or finding.get('module'))}",
        f"endpoint_type={_normalise_token(finding.get('endpoint_type'))}",
        f"parameter_type={_normalise_token(finding.get('parameter_type'))}",
        f"decision={_normalise_token(finding.get('decision') or finding.get('finding_decision'))}",
        f"host={_normalise_token(parsed.netloc or finding.get('host') or finding.get('target_host'))}",
    ]
    tokens.extend(f"path={part}" for part in path_parts)
    tokens.extend(f"signal={_normalise_token(signal)}" for signal in signals[:8])
    combined = str(finding.get("combined_signal") or "")
    tokens.extend(
        f"combined={_normalise_token(part)}" for part in combined.split("+") if part.strip()
    )
    return tokens


def _feature_vector(finding: dict[str, Any]) -> dict[str, float]:
    evidence = (
        cast(dict[str, Any], finding.get("evidence"))
        if isinstance(finding.get("evidence"), dict)
        else {}
    )
    diff = (
        cast(dict[str, Any], evidence.get("diff")) if isinstance(evidence.get("diff"), dict) else {}
    )
    features: dict[str, float] = {
        "bias": 1.0,
        "confidence": _clamp(
            _numeric(finding.get("confidence", finding.get("finding_confidence", 0.5)), 0.5)
        ),
        "legacy_impact": score_from_severity(
            finding.get("severity") or finding.get("finding_severity")
        )
        / 10.0,
        "cvss": _clamp(_numeric(finding.get("cvss_score"), 0.0) / 10.0),
        "score_hint": _clamp(_numeric(finding.get("score"), 0.0) / 100.0),
        "response_delta": _clamp(
            _numeric(
                finding.get("response_delta_score") or evidence.get("response_delta_score"), 0.0
            )
            / 10.0
        ),
        "diff_score": _clamp(
            _numeric(finding.get("diff_score") or evidence.get("diff_score"), 0.0) / 8.0
        ),
        "status_changed": 1.0 if diff.get("status_changed") else 0.0,
        "content_changed": 1.0 if diff.get("content_changed") else 0.0,
        "redirect_changed": 1.0 if diff.get("redirect_changed") else 0.0,
        "reproducible": 1.0
        if evidence.get("reproducible")
        or evidence.get("confirmed")
        or evidence.get("cross_run_reproducible")
        else 0.0,
    }
    for token in _tokens_from_finding(finding):
        features[f"token:{token}"] = 1.0
    return features


def _load_json(value: object) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if not value:
        return {}
    try:
        loaded = json.loads(str(value))
    except (TypeError, ValueError, json.JSONDecodeError):
        return {}
    return loaded if isinstance(loaded, dict) else {}


class CalibratedSeverityModel:
    """Train and serve calibrated severity scores from historical outcomes."""

    def __init__(self, db_path: str | Path | None = None, *, iterations: int = 14) -> None:
        self.db_path = Path(
            db_path
            or os.getenv("VULN_SEVERITY_DB_PATH")
            or os.getenv("PIPELINE_TELEMETRY_DB")
            or DEFAULT_DB_PATH
        )
        self.iterations = iterations
        self.weights: dict[str, float] = {}
        self.training_samples = 0
        self.global_tp_rate = 0.5
        self.category_rates: dict[str, tuple[int, int]] = {}
        self.plugin_rates: dict[str, tuple[int, int]] = {}
        self.param_rates: dict[str, tuple[int, int]] = {}

        # Initialize thread-safe registry and pipeline
        self.registry = ModelVersionRegistry()
        self.pipeline = XGBoostSeverityPipeline()

        self._train()

    @classmethod
    def from_default_store(cls) -> CalibratedSeverityModel:
        return get_default_severity_model()

    def predict(self, finding: dict[str, Any]) -> SeverityPrediction:
        # Check for active pipeline registered in registry
        pipeline = self.pipeline
        active_ver = MODEL_VERSION
        if hasattr(self, "registry") and self.registry:
            active_pipeline = self.registry._pipelines.get("severity_model")
            if active_pipeline:
                pipeline = active_pipeline
            active_model = self.registry._active.get("severity_model")
            if active_model:
                active_ver = active_model.version

        # Get raw probability from the pipeline
        raw_probability = pipeline.predict_probability(finding)

        calibrated_tp, calibration = self._calibrate(raw_probability, finding)
        input_impact = (
            score_from_severity(finding.get("severity") or finding.get("finding_severity")) / 10.0
        )
        cvss_impact = _clamp(_numeric(finding.get("cvss_score"), input_impact * 10.0) / 10.0)
        impact = _clamp((input_impact * 0.55) + (cvss_impact * 0.30) + (calibrated_tp * 0.15))
        score = round(_clamp((calibrated_tp * 0.72) + (impact * 0.28)) * 10.0, 2)
        severity = severity_from_score(score)
        confidence = round(
            _clamp(
                (self.training_samples / (self.training_samples + 40.0)) * 0.65
                + calibration["support"] * 0.35
            ),
            3,
        )
        features = _feature_vector(finding)
        return SeverityPrediction(
            score=score,
            severity=severity,
            true_positive_probability=round(calibrated_tp, 4),
            false_positive_probability=round(1.0 - calibrated_tp, 4),
            confidence=confidence,
            model_version=active_ver,
            training_samples=self.training_samples,
            calibration=calibration,
            top_features=self._top_features(features),
        )

    def enrich_finding(self, finding: dict[str, Any]) -> dict[str, Any]:
        prediction = self.predict(finding)
        metadata = prediction.as_metadata()
        return {
            **finding,
            "severity": prediction.severity,
            "severity_score": prediction.score,
            "score": prediction.score,
            "model_confidence": prediction.confidence,
            "true_positive_probability": prediction.true_positive_probability,
            "false_positive_probability": prediction.false_positive_probability,
            "severity_model": metadata,
        }

    def enrich_findings(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [self.enrich_finding(finding) for finding in findings]

    def aggregate_score(self, findings: list[dict[str, Any]]) -> float:
        if not findings:
            return 0.0
        scores = [
            self.predict(f).score if "severity_score" not in f else _numeric(f["severity_score"])
            for f in findings
        ]
        return round(sum(scores) / len(scores), 2)

    def _train(self) -> None:
        examples = self._load_training_examples()
        self.training_samples = len(examples)
        if not examples:
            self.weights = {
                "bias": 0.0,
                "confidence": 1.35,
                "legacy_impact": 1.0,
                "reproducible": 1.1,
            }
            return
        positives = sum(example.label * example.weight for example in examples)
        total_weight = sum(example.weight for example in examples) or 1.0
        self.global_tp_rate = _clamp(positives / total_weight, 0.02, 0.98)
        self.weights = {"bias": math.log(self.global_tp_rate / (1.0 - self.global_tp_rate))}
        learning_rate = 0.18
        l2 = 0.0008
        for _ in range(self.iterations):
            for example in examples:
                features = _feature_vector(example.finding)
                pred = self._sigmoid(sum(self.weights.get(k, 0.0) * v for k, v in features.items()))
                error = (example.label - pred) * example.weight
                for key, value in features.items():
                    current = self.weights.get(key, 0.0)
                    self.weights[key] = current + learning_rate * (error * value - l2 * current)
            learning_rate *= 0.86

        # Train new XGBoost/fallback pipeline
        try:
            findings_list = [ex.finding for ex in examples]
            labels_list = [ex.label for ex in examples]
            success = self.pipeline.fit(findings_list, labels_list)
            if success and self.pipeline.is_trained:
                new_version = f"severity-xgboost-v{int(time.time())}"
                mv = ModelVersion(
                    name="severity_model",
                    version=new_version,
                    metadata={
                        "samples": len(examples),
                        "retrained_at": time.time(),
                    }
                )
                self.registry.register(mv, activate=True, pipeline=self.pipeline)
        except Exception as e:
            logger.warning("SeverityModel: Pipeline retraining failed: %s", e)

    def _load_training_examples(self) -> list[_TrainingExample]:
        if not self.db_path.exists():
            return []
        try:
            with sqlite3.connect(f"file:{self.db_path}?mode=ro", uri=True) as conn:
                conn.row_factory = sqlite3.Row
                return self._load_feedback_examples(conn) + self._load_finding_examples(conn)
        except sqlite3.Error:
            return []

    def _load_feedback_examples(self, conn: sqlite3.Connection) -> list[_TrainingExample]:
        try:
            rows = conn.execute(
                """SELECT * FROM feedback_events
                   ORDER BY timestamp DESC
                   LIMIT 4000"""
            ).fetchall()
        except sqlite3.Error:
            return []
        examples: list[_TrainingExample] = []
        for row in rows:
            item = dict(row)
            category = _normalise_token(item.get("finding_category"))
            plugin = _normalise_token(item.get("plugin_name"))
            parameter_type = _normalise_token(item.get("parameter_type"))
            was_tp = bool(item.get("was_validated")) and not bool(item.get("was_false_positive"))
            was_fp = bool(item.get("was_false_positive"))
            if not was_tp and not was_fp:
                continue
            label = 1.0 if was_tp else 0.0
            weight = max(0.2, _numeric(item.get("feedback_weight"), 1.0))
            finding = {
                "category": category,
                "severity": item.get("finding_severity"),
                "confidence": item.get("finding_confidence"),
                "decision": item.get("finding_decision"),
                "plugin_name": plugin,
                "parameter_name": item.get("parameter_name"),
                "parameter_type": parameter_type,
                "endpoint_type": item.get("endpoint_type"),
                "url": item.get("target_endpoint"),
                "host": item.get("target_host"),
                "response_delta_score": item.get("response_delta_score"),
            }
            self._record_rate(self.category_rates, category, label)
            self._record_rate(self.plugin_rates, f"{category}|{plugin}", label)
            self._record_rate(self.param_rates, parameter_type, label)
            examples.append(_TrainingExample(finding=finding, label=label, weight=weight))
        return examples

    def _load_finding_examples(self, conn: sqlite3.Connection) -> list[_TrainingExample]:
        try:
            rows = conn.execute(
                """SELECT * FROM findings
                   WHERE lifecycle_state IN ('VALIDATED', 'EXPLOITABLE', 'REPORTABLE')
                      OR decision = 'DROP'
                   ORDER BY created_at DESC
                   LIMIT 2000"""
            ).fetchall()
        except sqlite3.Error:
            return []
        examples: list[_TrainingExample] = []
        for row in rows:
            item = dict(row)
            lifecycle = _normalise_token(item.get("lifecycle_state"))
            decision = _normalise_token(item.get("decision"))
            label = 1.0 if lifecycle in {"validated", "exploitable", "reportable"} else 0.0
            if decision == "drop":
                label = 0.0
            item["evidence"] = _load_json(item.get("evidence"))
            examples.append(_TrainingExample(finding=item, label=label, weight=0.65))
        return examples

    @staticmethod
    def _record_rate(bucket: dict[str, tuple[int, int]], key: str, label: float) -> None:
        positives, total = bucket.get(key, (0, 0))
        bucket[key] = (positives + int(label >= 0.5), total + 1)

    def _calibrate(
        self, raw_probability: float, finding: dict[str, Any]
    ) -> tuple[float, dict[str, float]]:
        category = _normalise_token(finding.get("category") or finding.get("finding_category"))
        plugin = _normalise_token(finding.get("plugin_name") or finding.get("module"))
        parameter_type = _normalise_token(finding.get("parameter_type"))
        rates = [
            self._smoothed_rate(self.category_rates.get(category, (0, 0)), strength=0.36),
            self._smoothed_rate(
                self.plugin_rates.get(f"{category}|{plugin}", (0, 0)), strength=0.42
            ),
            self._smoothed_rate(self.param_rates.get(parameter_type, (0, 0)), strength=0.22),
        ]
        total_support = sum(rate[1] for rate in rates)
        support = _clamp(total_support / 80.0)
        if total_support > 0:
            historical_tp = sum(rate[0] * rate[1] for rate in rates) / total_support
        else:
            historical_tp = self.global_tp_rate
        blend = _clamp(0.52 + support * 0.30)
        calibrated = _clamp(raw_probability * blend + historical_tp * (1.0 - blend), 0.01, 0.99)
        return calibrated, {
            "raw_probability": round(raw_probability, 4),
            "historical_true_positive_rate": round(historical_tp, 4),
            "historical_false_positive_rate": round(1.0 - historical_tp, 4),
            "support": round(support, 4),
        }

    def _smoothed_rate(self, counts: tuple[int, int], *, strength: float) -> tuple[float, int]:
        positives, total = counts
        prior_weight = 8.0 * strength
        numerator = positives + self.global_tp_rate * prior_weight
        denominator = total + prior_weight
        return (_clamp(numerator / max(1e-9, denominator), 0.01, 0.99), total)

    def _top_features(self, features: dict[str, float]) -> list[str]:
        ranked = sorted(
            (
                (abs(self.weights.get(key, 0.0) * value), key)
                for key, value in features.items()
                if key != "bias" and self.weights.get(key, 0.0)
            ),
            reverse=True,
        )
        return [key for _, key in ranked[:6]]

    @staticmethod
    def _sigmoid(value: float) -> float:
        if value >= 0:
            z = math.exp(-value)
            return 1.0 / (1.0 + z)
        z = math.exp(value)
        return z / (1.0 + z)


@lru_cache(maxsize=4)
def get_default_severity_model(db_path: str | Path | None = None) -> CalibratedSeverityModel:
    """Return a cached model trained from the telemetry database."""
    key_path = str(
        db_path
        or os.getenv("VULN_SEVERITY_DB_PATH")
        or os.getenv("PIPELINE_TELEMETRY_DB")
        or DEFAULT_DB_PATH
    )
    return CalibratedSeverityModel(key_path)


def enrich_finding_with_model_severity(finding: dict[str, Any]) -> dict[str, Any]:
    return get_default_severity_model().enrich_finding(finding)


def enrich_findings_with_model_severity(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return get_default_severity_model().enrich_findings(findings)


__all__ = [
    "CalibratedSeverityModel",
    "SeverityPrediction",
    "enrich_finding_with_model_severity",
    "enrich_findings_with_model_severity",
    "get_default_severity_model",
    "score_from_severity",
    "severity_from_score",
]
