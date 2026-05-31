"""Automated risk scoring engine.

Calculates comprehensive risk scores based on findings,
attack chains, and exposure analysis.
Runs automatically after scan completion.
"""

import math
from dataclasses import dataclass
from typing import Any

from src.intelligence.severity_model import (
    enrich_findings_with_model_severity,
    severity_from_score,
)


@dataclass
class RiskScore:
    """Comprehensive risk score result."""

    overall_score: float  # 0-10
    risk_level: str  # critical, high, medium, low, info
    category_scores: dict[str, float]
    factors: list[str]
    recommendations: list[str]

    def to_dashboard_json(self) -> dict[str, Any]:
        """Convert risk score to JSON schema structure for dashboard exposure.

        Returns:
            Dictionary matching the frontend dashboard metrics contract.
        """
        return {
            "overallScore": self.overall_score,
            "riskLevel": self.risk_level,
            "categoryScores": self.category_scores,
            "factors": self.factors,
            "recommendations": self.recommendations,
        }


class RiskScoringEngine:
    """Automated risk scoring based on calibrated model severity.

    API Schema Documentation:
        GET /api/v1/intelligence/risk/latest -> Returns latest RiskScore JSON
        GET /api/v1/intelligence/risk/history -> Returns list of past RiskScore JSONs
        WS  /ws/v1/intelligence/risk/stream   -> Real-time JSON WebSocket broadcast
    """

    def __init__(self) -> None:
        self._scores: list[RiskScore] = []

    def get_dashboard_summary(self) -> dict[str, Any]:
        """Expose current scoring state formatted specifically for the frontend API/dashboard.

        Returns:
            JSON-serializable summary of all calculated risk profiles.
        """
        latest = self.get_latest_score()
        return {
            "latestScore": latest.to_dashboard_json() if latest else None,
            "historyCount": len(self._scores),
            "historicalScores": [s.to_dashboard_json() for s in self._scores[-20:]],
            "apiEndpoints": {
                "get_latest_risk": "/api/v1/intelligence/risk/latest",
                "get_risk_history": "/api/v1/intelligence/risk/history",
                "websocket_updates": "/ws/v1/intelligence/risk/stream"
            }
        }

    def calculate_risk(
        self,
        findings: list[dict[str, Any]],
        attack_chains: list[Any] | None = None,
        sensitive_data: list[Any] | None = None,
        target_info: dict[str, Any] | None = None,
    ) -> RiskScore:
        """Calculate comprehensive risk score."""
        factors: list[str] = []
        category_scores: dict[str, float] = {}

        modeled_findings = enrich_findings_with_model_severity(findings)
        base_score = self._calculate_base_score(modeled_findings, factors)
        category_scores["vulnerability_score"] = base_score

        # Attack chain multiplier
        chain_multiplier = 1.0
        if attack_chains:
            chain_multiplier = self._calculate_chain_multiplier(attack_chains, factors)
            category_scores["attack_chain_score"] = chain_multiplier * 10

        # Sensitive data exposure
        data_score = 0.0
        if sensitive_data:
            data_score = self._calculate_data_exposure_score(sensitive_data, factors)
            category_scores["data_exposure_score"] = data_score

        # Target exposure
        exposure_score = 0.0
        if target_info:
            exposure_score = self._calculate_exposure_score(target_info, factors)
            category_scores["exposure_score"] = exposure_score

        # Calculate final score
        final_score = base_score * chain_multiplier
        if data_score > 0:
            final_score = min(10, final_score + (data_score / 10))
        if exposure_score > 0:
            final_score = min(10, final_score + (exposure_score / 10))

        # Generate recommendations
        recommendations = self._generate_recommendations(
            modeled_findings, attack_chains, sensitive_data
        )

        risk_level = severity_from_score(final_score)

        score = RiskScore(
            overall_score=round(final_score, 1),
            risk_level=risk_level,
            category_scores=category_scores,
            factors=factors,
            recommendations=recommendations,
        )
        self._scores.append(score)
        return score

    def _calculate_base_score(self, findings: list[dict[str, Any]], factors: list[str]) -> float:
        """Calculate base score from findings."""
        if not findings:
            return 0.0

        severity_counts: dict[str, int] = {
            label: 0 for label in ("critical", "high", "medium", "low", "info")
        }
        score_total = 0.0
        for f in findings:
            sev = f.get("severity", "info").lower()
            if sev in severity_counts:
                severity_counts[sev] += 1
            score_total += float(f.get("severity_score", 0.0))

        # Logarithmic scaling to prevent extreme scores
        total_findings = len(findings)
        quantity_factor = 1 + math.log10(total_findings + 1)

        base_score = min(10, (score_total / max(1, total_findings)) * quantity_factor)

        if severity_counts["critical"] > 0:
            factors.append(f"{severity_counts['critical']} critical vulnerabilities found")
        if severity_counts["high"] > 0:
            factors.append(f"{severity_counts['high']} high severity vulnerabilities found")
        if total_findings > 20:
            factors.append(f"High vulnerability density: {total_findings} findings")

        return base_score

    def _calculate_chain_multiplier(self, chains: list[Any], factors: list[str]) -> float:
        """Calculate multiplier based on attack chains."""
        critical_chains = sum(1 for c in chains if getattr(c, "severity", "") == "critical")
        high_chains = sum(1 for c in chains if getattr(c, "severity", "") == "high")

        multiplier = 1.0 + (critical_chains * 0.3) + (high_chains * 0.15)

        if critical_chains > 0:
            factors.append(f"{critical_chains} critical attack chains discovered")
        if high_chains > 0:
            factors.append(f"{high_chains} high severity attack chains discovered")

        return min(2.0, multiplier)  # Cap at 2x

    def _calculate_data_exposure_score(
        self, sensitive_data: list[Any], factors: list[str]
    ) -> float:
        """Calculate score based on sensitive data exposure."""
        critical_data = sum(1 for d in sensitive_data if getattr(d, "severity", "") == "critical")
        high_data = sum(1 for d in sensitive_data if getattr(d, "severity", "") == "high")

        score = (critical_data * 3) + (high_data * 1.5)

        if critical_data > 0:
            factors.append(f"Critical data exposure: {critical_data} instances")

        return min(10, score)

    def _calculate_exposure_score(self, target_info: dict[str, Any], factors: list[str]) -> float:
        """Calculate score based on target exposure."""
        score = 0.0

        if target_info.get("is_public", False):
            score += 2
            factors.append("Target is publicly accessible")

        if target_info.get("has_pii", False):
            score += 3
            factors.append("Target handles personally identifiable information")

        if target_info.get("has_financial", False):
            score += 3
            factors.append("Target handles financial data")

        if target_info.get("compliance_requirements"):
            score += 2
            factors.append(
                f"Compliance requirements: {', '.join(target_info['compliance_requirements'])}"
            )

        return min(10, score)

    def _generate_recommendations(
        self,
        findings: list[dict[str, Any]],
        chains: list[Any] | None,
        sensitive_data: list[Any] | None,
    ) -> list[str]:
        """Generate actionable recommendations."""
        recs: list[str] = []

        # Based on findings
        vuln_types = {f.get("type", "") for f in findings}

        if "sqli" in vuln_types:
            recs.append("Implement parameterized queries and input validation")
        if "xss" in vuln_types:
            recs.append("Implement Content Security Policy and output encoding")
        if "auth_bypass" in vuln_types:
            recs.append("Review authentication and authorization mechanisms")
        if "idor" in vuln_types:
            recs.append("Implement proper access control checks on all endpoints")

        # Based on chains
        if chains:
            recs.append("Prioritize fixing vulnerabilities that form attack chains")

        # Based on sensitive data
        if sensitive_data:
            recs.append("Implement data loss prevention controls")
            recs.append("Review and restrict sensitive data exposure in responses")

        if not recs:
            recs.append("Continue monitoring and regular security testing")

        return recs

    def get_latest_score(self) -> RiskScore | None:
        """Get the most recently calculated risk score."""
        return self._scores[-1] if self._scores else None
