"""ML-backed severity scoring facade for security findings."""

from __future__ import annotations

from typing import Any

from src.core.logging.trace_logging import get_pipeline_logger
from src.intelligence.severity_model import CalibratedSeverityModel

logger = get_pipeline_logger(__name__)


class NeuralScorer:
    """Compatibility wrapper around the calibrated severity model."""

    def __init__(self, model: CalibratedSeverityModel | None = None) -> None:
        self.model = model or CalibratedSeverityModel.from_default_store()

    def calculate_csi(self, finding: dict[str, Any], target_criticality: float = 0.5) -> float:
        """Calculate the 0.0-10.0 calibrated severity score."""
        enriched = dict(finding)
        enriched.setdefault("target_criticality", target_criticality)
        return self.model.predict(enriched).score

    def rank_findings(
        self, findings: list[dict[str, Any]], target_map: dict[str, float]
    ) -> list[dict[str, Any]]:
        """Attach calibrated model severity to each finding and rank descending."""
        ranked: list[dict[str, Any]] = []
        for finding in findings:
            target = str(finding.get("target") or finding.get("host") or "unknown")
            criticality = target_map.get(target, 0.5)
            enriched_input = {**finding, "target_criticality": criticality}
            enriched = self.model.enrich_finding(enriched_input)
            enriched["csi_score"] = enriched["severity_score"]
            ranked.append(enriched)
        return sorted(ranked, key=lambda item: float(item.get("severity_score", 0.0)), reverse=True)


def apply_neural_scoring(
    findings: list[dict[str, Any]], target_map: dict[str, float]
) -> list[dict[str, Any]]:
    """Apply calibrated ML severity scoring."""
    scorer = NeuralScorer()
    return scorer.rank_findings(findings, target_map)
