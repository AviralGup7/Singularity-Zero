"""Pydantic schemas and extractor utilities for finding feature vectors."""

from __future__ import annotations

from typing import Any, cast
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field


def _numeric(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    return max(low, min(high, value))


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


def score_from_severity(severity: object) -> float:
    """Return the impact prior for a legacy/input severity label."""
    severity_to_impact = {
        "info": 0.10,
        "low": 0.28,
        "medium": 0.52,
        "high": 0.78,
        "critical": 1.00,
    }
    return severity_to_impact.get(str(severity or "info").strip().lower(), 0.35) * 10.0


class FeatureVector(BaseModel):
    """Pydantic validated tabular representation of finding characteristics."""

    model_config = ConfigDict(strict=True)

    bias: float = 1.0
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    legacy_impact: float = Field(default=0.35, ge=0.0, le=1.0)
    cvss: float = Field(default=0.0, ge=0.0, le=1.0)
    score_hint: float = Field(default=0.0, ge=0.0, le=1.0)
    response_delta: float = Field(default=0.0, ge=0.0, le=1.0)
    diff_score: float = Field(default=0.0, ge=0.0, le=1.0)
    status_changed: float = Field(default=0.0, ge=0.0, le=1.0)
    content_changed: float = Field(default=0.0, ge=0.0, le=1.0)
    redirect_changed: float = Field(default=0.0, ge=0.0, le=1.0)
    reproducible: float = Field(default=0.0, ge=0.0, le=1.0)
    tokens: list[str] = Field(default_factory=list)

    @classmethod
    def from_finding(cls, finding: dict[str, Any]) -> FeatureVector:
        """Parse and validate a raw finding dictionary into a FeatureVector."""
        evidence = (
            cast(dict[str, Any], finding.get("evidence"))
            if isinstance(finding.get("evidence"), dict)
            else {}
        )
        diff = (
            cast(dict[str, Any], evidence.get("diff"))
            if isinstance(evidence.get("diff"), dict)
            else {}
        )

        # Safe extraction of numerical features
        confidence = _clamp(
            _numeric(finding.get("confidence", finding.get("finding_confidence", 0.5)), 0.5)
        )
        legacy_impact = _clamp(
            score_from_severity(finding.get("severity") or finding.get("finding_severity")) / 10.0
        )
        cvss = _clamp(_numeric(finding.get("cvss_score"), 0.0) / 10.0)
        score_hint = _clamp(_numeric(finding.get("score"), 0.0) / 100.0)
        response_delta = _clamp(
            _numeric(
                finding.get("response_delta_score") or evidence.get("response_delta_score"), 0.0
            )
            / 10.0
        )
        diff_score = _clamp(
            _numeric(finding.get("diff_score") or evidence.get("diff_score"), 0.0) / 10.0
        )

        # Categorical token parsing
        tokens = _tokens_from_finding(finding)

        return cls(
            confidence=confidence,
            legacy_impact=legacy_impact,
            cvss=cvss,
            score_hint=score_hint,
            response_delta=response_delta,
            diff_score=diff_score,
            status_changed=1.0 if diff.get("status_changed") else 0.0,
            content_changed=1.0 if diff.get("content_changed") else 0.0,
            redirect_changed=1.0 if diff.get("redirect_changed") else 0.0,
            reproducible=1.0
            if (
                evidence.get("reproducible")
                or evidence.get("confirmed")
                or evidence.get("cross_run_reproducible")
            )
            else 0.0,
            tokens=tokens,
        )

    def to_features_dict(self) -> dict[str, float]:
        """Convert standard numeric features and token indicators to a flat model dictionary."""
        feats = {
            "bias": self.bias,
            "confidence": self.confidence,
            "legacy_impact": self.legacy_impact,
            "cvss": self.cvss,
            "score_hint": self.score_hint,
            "response_delta": self.response_delta,
            "diff_score": self.diff_score,
            "status_changed": self.status_changed,
            "content_changed": self.content_changed,
            "redirect_changed": self.redirect_changed,
            "reproducible": self.reproducible,
        }
        for token in self.tokens:
            feats[f"token:{token}"] = 1.0
        return feats
