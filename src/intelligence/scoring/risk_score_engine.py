"""Automated risk scoring engine.

Calculates comprehensive risk scores based on findings,
attack chains, and exposure analysis.
Runs automatically after scan completion.

The engine now produces two parallel scores:

* ``csi_value`` - the legacy 0-10 vulnerability score carried over
  for backward compatibility.
* ``modern_risk_score`` - the new 0-100 multi-dimensional score
  that incorporates asset criticality, business context,
  compensating controls, EPSS / CISA KEV, attack chain
  amplification, and the calibrated model TP probability.

The composite formula lives in
:mod:`src.intelligence.risk.modern_risk` so the rest of the
platform can use it without depending on this module.
"""

from __future__ import annotations

import logging
import math
from dataclasses import dataclass, field
from typing import Any

from src.intelligence.severity_model import (
    enrich_findings_with_model_severity,
    severity_from_score,
)

logger = logging.getLogger(__name__)


@dataclass
class RiskScore:
    """Comprehensive risk score result."""

    overall_score: float  # 0-10 (legacy)
    risk_level: str  # critical, high, medium, low, info
    category_scores: dict[str, float]
    factors: list[str]
    recommendations: list[str]
    modern_risk_score: float = 0.0  # 0-100
    modern_risk_components: dict[str, float] = field(default_factory=dict)
    modern_risk_reasons: list[str] = field(default_factory=list)
    asset_context: dict[str, Any] | None = None
    acceptance_suppressed_count: int = 0

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
            "modernRiskScore": self.modern_risk_score,
            "modernRiskComponents": self.modern_risk_components,
            "modernRiskReasons": self.modern_risk_reasons,
            "assetContext": self.asset_context,
            "acceptanceSuppressedCount": self.acceptance_suppressed_count,
        }


# Maximum amplification a single attack chain can contribute. The
# legacy engine used a hard-coded 2x cap; the modern engine exposes
# this as a configuration knob so orgs with mature red teams can
# crank it up.
DEFAULT_CHAIN_AMPLIFICATION_CAP = 2.0


class RiskScoringEngine:
    """Automated risk scoring based on calibrated model severity.

    API Schema Documentation:
        GET /api/v1/intelligence/risk/latest -> Returns latest RiskScore JSON
        GET /api/v1/intelligence/risk/history -> Returns list of past RiskScore JSONs
        WS  /ws/v1/intelligence/risk/stream   -> Real-time JSON WebSocket broadcast
    """

    def __init__(
        self,
        *,
        chain_amplification_cap: float = DEFAULT_CHAIN_AMPLIFICATION_CAP,
        modern_calculator: Any | None = None,
        priority_calculator: Any | None = None,
    ) -> None:
        self._scores: list[RiskScore] = []
        self._chain_amplification_cap = max(1.0, float(chain_amplification_cap))
        self._modern_calculator = modern_calculator
        self._priority_calculator = priority_calculator

    # ------------------------------------------------------------------
    # Public API (preserved)
    # ------------------------------------------------------------------

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
                "websocket_updates": "/ws/v1/intelligence/risk/stream",
            },
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

        target_info = target_info or {}
        host_or_url = str(target_info.get("url") or target_info.get("host") or "")
        business_context = target_info.get("business_context") or {}

        # 1. Run findings through the calibrated severity model.
        modeled_findings = enrich_findings_with_model_severity(findings)
        base_score = self._calculate_base_score(modeled_findings, factors)
        category_scores["vulnerability_score"] = base_score

        # 2. Compute chain amplification (now configurable).
        chain_multiplier = 1.0
        chain_amplification_per_finding: dict[str, float] = {}
        if attack_chains:
            chain_multiplier, chain_amplification_per_finding = self._calculate_chain_multiplier(
                attack_chains, factors
            )
            category_scores["attack_chain_score"] = chain_multiplier * 10

        # 3. Sensitive data exposure.
        data_score = 0.0
        if sensitive_data:
            data_score = self._calculate_data_exposure_score(sensitive_data, factors)
            category_scores["data_exposure_score"] = data_score

        # 4. Multi-dimensional exposure / context.
        exposure_score, exposure_factors = self._calculate_exposure_score(
            target_info, factors
        )
        if exposure_score > 0:
            category_scores["exposure_score"] = exposure_score

        # 5. Compute the *modern* risk score. This is the new
        #    multi-dimensional blend that the dashboard surfaces
        #    alongside the legacy CSI value.
        (
            modern_score,
            modern_components,
            modern_reasons,
            asset_context_dict,
            suppressed_count,
        ) = self._calculate_modern_risk(
            modeled_findings,
            target_info=target_info,
            host_or_url=host_or_url,
            business_context=business_context,
            chain_amplification_per_finding=chain_amplification_per_finding,
        )
        category_scores["modern_risk_score"] = modern_score

        # 6. Final composite (legacy). Kept for the dashboard's
        #    "overallScore" field.
        final_score = base_score * chain_multiplier
        if data_score > 0:
            final_score = min(10, final_score + (data_score / 10))
        if exposure_score > 0:
            final_score = min(10, final_score + (exposure_score / 10))
        if modern_components:
            # Lightweight nudge: if the modern blend flags a
            # crown-jewel asset, raise the legacy final score
            # proportionally so older dashboards show *something*.
            uplift = float(modern_components.get("asset_criticality", 0.0)) / 20.0
            if uplift > 0:
                final_score = min(10, final_score + uplift)
                factors.append(
                    f"Asset criticality uplift: +{round(uplift, 2)}"
                )

        # Generate recommendations
        recommendations = self._generate_recommendations(
            modeled_findings, attack_chains, sensitive_data
        )
        # Modern risk reasons double as a contextual hint for analysts.
        for reason in modern_reasons:
            recommendations.append(f"Modern risk: {reason}")

        risk_level = severity_from_score(final_score)

        score = RiskScore(
            overall_score=round(final_score, 1),
            risk_level=risk_level,
            category_scores=category_scores,
            factors=factors + exposure_factors,
            recommendations=recommendations,
            modern_risk_score=round(modern_score, 2),
            modern_risk_components=modern_components,
            modern_risk_reasons=modern_reasons,
            asset_context=asset_context_dict,
            acceptance_suppressed_count=suppressed_count,
        )
        self._scores.append(score)
        return score

    # ------------------------------------------------------------------
    # Modern risk composition
    # ------------------------------------------------------------------

    def _calculate_modern_risk(
        self,
        findings: list[dict[str, Any]],
        *,
        target_info: dict[str, Any],
        host_or_url: str,
        business_context: dict[str, Any],
        chain_amplification_per_finding: dict[str, float],
    ) -> tuple[float, dict[str, float], list[str], dict[str, Any] | None, int]:
        calculator = self._modern_calculator
        if calculator is None:
            try:
                from src.intelligence.risk.modern_risk import (
                    get_default_modern_risk_calculator,
                )

                calculator = get_default_modern_risk_calculator()
            except Exception as exc:  # noqa: BLE001
                logger.debug("Modern risk calculator unavailable: %s", exc)
                return 0.0, {}, [], None, 0

        if not findings:
            try:
                score = calculator.for_finding(
                    {},
                    host_or_url=host_or_url,
                    target_info=target_info,
                    business_context=business_context,
                )
            except Exception as exc:  # noqa: BLE001
                logger.debug("Modern risk (empty findings) failed: %s", exc)
                return 0.0, {}, [], None, 0
            return (
                score.modern_risk_score,
                score.components,
                score.reason_codes,
                score.asset_context.to_dict() if score.asset_context else None,
                1 if score.acceptance_suppressed else 0,
            )

        per_finding_scores: list[Any] = []
        suppressed = 0
        aggregated_components: dict[str, float] = {}
        aggregated_reasons: list[str] = []
        asset_context_dict: dict[str, Any] | None = None
        for finding in findings:
            finding_id = str(finding.get("id") or finding.get("finding_id") or "")
            chain_amp = chain_amplification_per_finding.get(finding_id, 1.0)
            try:
                score = calculator.for_finding(
                    finding,
                    host_or_url=host_or_url or str(finding.get("url") or finding.get("host") or ""),
                    target_info=target_info,
                    business_context=business_context,
                    chain_amplification=chain_amp,
                )
            except Exception as exc:  # noqa: BLE001
                logger.debug("Modern risk per-finding calc failed: %s", exc)
                continue
            per_finding_scores.append(score)
            if score.acceptance_suppressed:
                suppressed += 1
            for key, value in score.components.items():
                aggregated_components[key] = aggregated_components.get(key, 0.0) + float(value)
            for reason in score.reason_codes:
                if reason not in aggregated_reasons:
                    aggregated_reasons.append(reason)
            if asset_context_dict is None and score.asset_context is not None:
                asset_context_dict = score.asset_context.to_dict()

        if not per_finding_scores:
            return 0.0, {}, [], asset_context_dict, suppressed

        # Average the components but use the *max* modern_risk_score
        # so a single extreme finding still drives the headline.
        max_score = max(s.modern_risk_score for s in per_finding_scores)
        avg_score = sum(s.modern_risk_score for s in per_finding_scores) / len(per_finding_scores)
        composite = max(max_score, avg_score)

        count = max(1, len(per_finding_scores))
        for key in list(aggregated_components):
            aggregated_components[key] = round(aggregated_components[key] / count, 3)

        return composite, aggregated_components, aggregated_reasons, asset_context_dict, suppressed

    # ------------------------------------------------------------------
    # Legacy scoring (preserved, with light modernisation)
    # ------------------------------------------------------------------

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

    def _calculate_chain_multiplier(
        self, chains: list[Any], factors: list[str]
    ) -> tuple[float, dict[str, float]]:
        """Calculate multiplier based on attack chains.

        Returns a (multiplier, per_finding_amplification) tuple. The
        per-finding mapping is used by the modern risk calculator to
        amplify individual findings that belong to high-severity
        chains. The legacy global multiplier is preserved for the
        ``overallScore`` calculation.
        """
        severity_to_amp = {
            "critical": 1.7,
            "high": 1.3,
            "medium": 1.15,
            "low": 1.05,
        }
        per_finding: dict[str, float] = {}
        critical_chains = 0
        high_chains = 0
        for chain in chains:
            severity = str(getattr(chain, "severity", "") or "").lower()
            if severity not in severity_to_amp:
                continue
            amp = severity_to_amp[severity]
            for step in getattr(chain, "steps", []) or []:
                if not isinstance(step, dict):
                    continue
                step_id = str(step.get("id") or step.get("finding_id") or "")
                if not step_id:
                    continue
                per_finding[step_id] = max(per_finding.get(step_id, 1.0), amp)
            if severity == "critical":
                critical_chains += 1
            elif severity == "high":
                high_chains += 1

        multiplier = 1.0 + (critical_chains * 0.3) + (high_chains * 0.15)
        cap = self._chain_amplification_cap
        multiplier = min(cap, multiplier)

        if critical_chains > 0:
            factors.append(f"{critical_chains} critical attack chains discovered")
        if high_chains > 0:
            factors.append(f"{high_chains} high severity attack chains discovered")
        if per_finding:
            factors.append(
                f"Attack chain amplification applied to {len(per_finding)} finding(s) (cap {cap}x)"
            )

        return multiplier, per_finding

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

    def _calculate_exposure_score(
        self, target_info: dict[str, Any], factors: list[str]
    ) -> tuple[float, list[str]]:
        """Calculate the *multi-dimensional* exposure score.

        Replaces the legacy ``+2 / +3`` additive bonuses with a
        structured contribution from:

        * Asset criticality (crown-jewel uplift)
        * Business context (PII, payment, compliance)
        * Compensating control discount (already applied to
          individual finding scores; surfaced here as a factor)
        * Network exposure (public vs internal)

        Returns a 0-10 score and a list of factor strings describing
        the contributions.
        """
        score = 0.0
        factor_strings: list[str] = []

        # Asset criticality contribution (0-5).
        asset_criticality = float(target_info.get("criticality", 0.0) or 0.0)
        if asset_criticality > 0:
            asset_component = min(5.0, asset_criticality / 2.0)
            score += asset_component
            factor_strings.append(
                f"Asset criticality: {round(asset_criticality, 1)} (crown-jewel uplift)"
            )

        if target_info.get("is_public", False):
            score += 2
            factor_strings.append("Target is publicly accessible")

        if target_info.get("has_pii", False):
            score += 3
            factor_strings.append("Target handles personally identifiable information")

        if target_info.get("has_financial", False):
            score += 3
            factor_strings.append("Target handles financial data")

        compliance = target_info.get("compliance_requirements")
        if compliance:
            score += 2
            factor_strings.append(
                f"Compliance requirements: {', '.join(compliance)}"
            )

        # Compensating control presence *reduces* the exposure score.
        # The score is the *gross* exposure; net residual is computed
        # elsewhere.
        controls = target_info.get("compensating_controls")
        if isinstance(controls, list) and controls:
            control_factor = max(0.1, 1.0 - 0.15 * len(controls))
            score = score * control_factor
            factor_strings.append(
                f"Compensating controls present ({len(controls)}) -> discount {round(1 - control_factor, 2)}"
            )

        return min(10, score), factor_strings

    def _generate_recommendations(
        self,
        findings: list[dict[str, Any]],
        chains: list[Any] | None,
        sensitive_data: list[Any] | None,
    ) -> list[str]:
        """Generate actionable recommendations."""
        recs: list[str] = []

        vuln_types = {f.get("type", "") for f in findings}

        if "sqli" in vuln_types:
            recs.append("Implement parameterized queries and input validation")
        if "xss" in vuln_types:
            recs.append("Implement Content Security Policy and output encoding")
        if "auth_bypass" in vuln_types:
            recs.append("Review authentication and authorization mechanisms")
        if "idor" in vuln_types:
            recs.append("Implement proper access control checks on all endpoints")

        if chains:
            recs.append("Prioritize fixing vulnerabilities that form attack chains")

        if sensitive_data:
            recs.append("Implement data loss prevention controls")
            recs.append("Review and restrict sensitive data exposure in responses")

        if not recs:
            recs.append("Continue monitoring and regular security testing")

        return recs

    def get_latest_score(self) -> RiskScore | None:
        """Get the most recently calculated risk score."""
        return self._scores[-1] if self._scores else None


__all__ = [
    "DEFAULT_CHAIN_AMPLIFICATION_CAP",
    "RiskScore",
    "RiskScoringEngine",
]
