"""
Cyber Security Test Pipeline - Neural-Score Engine
Implements sophisticated multi-dimensional risk scoring for security findings.
"""

from __future__ import annotations

from typing import Any

import numpy as np

from src.core.logging.trace_logging import get_pipeline_logger

logger = get_pipeline_logger(__name__)

class NeuralScorer:
    """
    Frontier Risk Engine.
    Calculates the Composite Severity Index (CSI) using multi-factor weighting.
    """
    def __init__(self) -> None:
        # Weights for the CSI calculation
        self.weights = {
            "cvss_base": 0.40,
            "confidence": 0.20,
            "business_impact": 0.25,
            "exploitability": 0.15
        }

    def calculate_csi(self, finding: dict[str, Any], target_criticality: float = 0.5) -> float:
        """
        Calculate the 0.0 - 10.0 CSI score.
        """
        # 1. Normalized CVSS (0-10)
        cvss = float(finding.get("cvss_score", 5.0))

        # 2. Confidence (0-1)
        confidence = float(finding.get("confidence", 0.5))

        # 3. Exploitability (Inferred from type)
        type_str = finding.get("type", "").lower()
        exploitability = 0.9 if any(x in type_str for x in ["rce", "sqli", "idor"]) else 0.4

        # 4. Neural-Mesh Consensus factor
        # If multiple tools found it, boost confidence
        sources = finding.get("metadata", {}).get("sources", [])
        if len(sources) > 1:
            confidence = min(1.0, confidence * 1.2)

        # Vectorized Weighted Calculation
        factors = np.array([cvss, confidence * 10, target_criticality * 10, exploitability * 10])
        weights = np.array([self.weights["cvss_base"], self.weights["confidence"],
                           self.weights["business_impact"], self.weights["exploitability"]])

        csi = np.dot(factors, weights)
        return round(float(csi), 2)

    def rank_findings(self, findings: list[dict[str, Any]], target_map: dict[str, float]) -> list[dict[str, Any]]:
        """
        Rank all findings across the mesh based on their CSI.
        """
        for finding in findings:
            target = finding.get("target", "unknown")
            criticality = target_map.get(target, 0.5)
            finding["csi_score"] = self.calculate_csi(finding, criticality)

            # Map back to human severity based on CSI
            if finding["csi_score"] >= 9.0:
                finding["severity"] = "critical"
            elif finding["csi_score"] >= 7.0:
                finding["severity"] = "high"
            elif finding["csi_score"] >= 4.0:
                finding["severity"] = "medium"
            else:
                finding["severity"] = "low"

        return sorted(findings, key=lambda x: x["csi_score"], reverse=True)

def apply_neural_scoring(findings: list[dict[str, Any]], target_map: dict[str, float]) -> list[dict[str, Any]]:
    """Helper to apply the highest-tier risk scoring."""
    scorer = NeuralScorer()
    return scorer.rank_findings(findings, target_map)
