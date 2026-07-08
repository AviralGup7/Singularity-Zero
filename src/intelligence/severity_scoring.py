"""Scoring helpers for the calibrated severity model.

Re-exports from severity_model for backward compatibility.
"""

from src.intelligence.severity_model import (
    CalibratedSeverityModel,
    SeverityPrediction,
    enrich_finding_with_model_severity,
    enrich_findings_with_model_severity,
    get_default_severity_model,
    score_from_severity,
    severity_from_score,
)

__all__ = [
    "CalibratedSeverityModel",
    "SeverityPrediction",
    "enrich_finding_with_model_severity",
    "enrich_findings_with_model_severity",
    "get_default_severity_model",
    "score_from_severity",
    "severity_from_score",
]
