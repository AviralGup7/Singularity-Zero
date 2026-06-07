"""Composite remediation priority score.

Combines the modern risk dimensions into a single 0-100 priority
that is suitable for default finding ordering in
``FindingsPage`` / Kanban views. The composite is intentionally
transparent (every component is exposed in the returned dict) so
analysts can drill into *why* a finding is at the top of the
queue.

Formula (configurable, defaults shown)::

    priority = (
        modern_risk_score  * 0.30
      + attack_chain_weight * 0.25
      + epss_score * 100    * 0.20
      + asset_criticality   * 0.15 * 10
      + analyst_tp_rate     * 0.10 * 100
    )
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import asdict, dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


DEFAULT_PRIORITY_WEIGHTS: dict[str, float] = {
    "modern_risk": 0.30,
    "attack_chain": 0.25,
    "epss": 0.20,
    "asset_criticality": 0.15,
    "analyst_tp_rate": 0.10,
}


@dataclass
class PriorityWeights:
    """Weights for each component of the composite priority."""

    modern_risk: float = DEFAULT_PRIORITY_WEIGHTS["modern_risk"]
    attack_chain: float = DEFAULT_PRIORITY_WEIGHTS["attack_chain"]
    epss: float = DEFAULT_PRIORITY_WEIGHTS["epss"]
    asset_criticality: float = DEFAULT_PRIORITY_WEIGHTS["asset_criticality"]
    analyst_tp_rate: float = DEFAULT_PRIORITY_WEIGHTS["analyst_tp_rate"]

    def to_dict(self) -> dict[str, float]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> PriorityWeights:
        return cls(
            modern_risk=float(payload.get("modern_risk", cls.modern_risk)),
            attack_chain=float(payload.get("attack_chain", cls.attack_chain)),
            epss=float(payload.get("epss", cls.epss)),
            asset_criticality=float(payload.get("asset_criticality", cls.asset_criticality)),
            analyst_tp_rate=float(payload.get("analyst_tp_rate", cls.analyst_tp_rate)),
        )

    def total(self) -> float:
        return (
            self.modern_risk
            + self.attack_chain
            + self.epss
            + self.asset_criticality
            + self.analyst_tp_rate
        )


@dataclass
class RemediationPriority:
    """A single finding's remediation priority breakdown."""

    finding_id: str
    priority: float
    components: dict[str, float]
    weights: dict[str, float]
    rank: int = 0
    reason_codes: list[str] = field(default_factory=list)
    computed_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "priority": round(self.priority, 2),
            "components": {k: round(v, 3) for k, v in self.components.items()},
            "weights": dict(self.weights),
            "rank": self.rank,
            "reason_codes": list(self.reason_codes),
            "computed_at": self.computed_at,
        }


class RemediationPriorityCalculator:
    """Calculate a composite ``RemediationPriority`` for each finding."""

    def __init__(self, weights: PriorityWeights | None = None) -> None:
        self.weights = weights or PriorityWeights()

    # -- public --------------------------------------------------------

    def for_finding(self, finding: dict[str, Any]) -> RemediationPriority:
        components = {
            "modern_risk": _clamp(_numeric(finding.get("modern_risk_score")), 0.0, 10.0),
            "attack_chain": _clamp(_numeric(finding.get("attack_chain_weight")), 0.0, 10.0),
            "epss": _clamp(_numeric(_epss_for_finding(finding)), 0.0, 1.0) * 10.0,
            "asset_criticality": _clamp(_numeric(finding.get("asset_criticality_score")), 0.0, 10.0),
            "analyst_tp_rate": _clamp(_numeric(finding.get("analyst_tp_rate")), 0.0, 1.0) * 10.0,
        }
        weights = self.weights.to_dict()
        total_weight = self.weights.total() or 1.0
        weighted = sum(components[key] * weights[key] for key in components)
        priority = (weighted / total_weight) * 10.0  # scale to 0-100
        return RemediationPriority(
            finding_id=str(finding.get("id") or finding.get("finding_id") or ""),
            priority=round(_clamp(priority, 0.0, 100.0), 2),
            components=components,
            weights=weights,
            reason_codes=_priority_reason_codes(finding, components),
        )

    def rank_findings(self, findings: list[dict[str, Any]]) -> list[RemediationPriority]:
        scored = [self.for_finding(f) for f in findings]
        scored.sort(key=lambda p: p.priority, reverse=True)
        for index, priority in enumerate(scored, start=1):
            priority.rank = index
        return scored

    def attach_to_findings(
        self, findings: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        ranked = self.rank_findings(findings)
        by_id = {p.finding_id: p for p in ranked}
        enriched: list[dict[str, Any]] = []
        for finding in findings:
            finding_id = str(finding.get("id") or finding.get("finding_id") or "")
            priority = by_id.get(finding_id)
            if priority is None:
                priority = self.for_finding(finding)
            enriched.append(
                {
                    **finding,
                    "remediation_priority": priority.priority,
                    "remediation_priority_components": priority.components,
                    "remediation_priority_reasons": priority.reason_codes,
                    "remediation_priority_rank": priority.rank,
                }
            )
        return enriched


# ---------------------------------------------------------------------------
# Module-level helper
# ---------------------------------------------------------------------------

_default_lock = threading.Lock()
_default_calculator: RemediationPriorityCalculator | None = None


def get_default_priority_calculator() -> RemediationPriorityCalculator:
    global _default_calculator
    with _default_lock:
        if _default_calculator is None:
            _default_calculator = RemediationPriorityCalculator()
        return _default_calculator


def reset_default_priority_calculator() -> None:
    global _default_calculator
    with _default_lock:
        _default_calculator = None


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


def _clamp(value: float, low: float, high: float) -> float:
    return max(low, min(high, float(value)))


def _numeric(value: Any, default: float = 0.0) -> float:
    if value is None or value == "":
        return default
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _epss_for_finding(finding: dict[str, Any]) -> float:
    threat_intel = finding.get("threat_intel") or {}
    raw = threat_intel.get("epss_score")
    if raw is None:
        raw = finding.get("epss_score")
    return _numeric(raw)


def _priority_reason_codes(
    finding: dict[str, Any], components: dict[str, float]
) -> list[str]:
    codes: list[str] = []
    if components["epss"] >= 5.0:
        codes.append("epss_high")
    threat_intel = finding.get("threat_intel") or {}
    if threat_intel.get("cisa_kev"):
        codes.append("cisa_kev")
    if components["attack_chain"] >= 3.0:
        codes.append("in_attack_chain")
    if components["asset_criticality"] >= 7.0:
        codes.append("crown_jewel_asset")
    if components["modern_risk"] >= 8.0:
        codes.append("critical_modern_risk")
    if components["analyst_tp_rate"] >= 7.0:
        codes.append("analyst_confirmed_tp")
    return codes


__all__ = [
    "DEFAULT_PRIORITY_WEIGHTS",
    "PriorityWeights",
    "RemediationPriority",
    "RemediationPriorityCalculator",
    "get_default_priority_calculator",
    "reset_default_priority_calculator",
]
