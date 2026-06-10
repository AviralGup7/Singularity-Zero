"""Modern multi-dimensional risk score.

Replaces the legacy ``severity_model`` impact blend with a
configurable composite that incorporates:

* Modern CVSS 4.0 base (and threat-intel weighted score)
* EPSS exploitation probability
* CISA KEV flag
* Asset criticality (1-10)
* Business entity multiplier (payment_processor > 1.0, docs < 1.0)
* Compensating control discount
* Attack chain amplification
* Threat actor capability (optional org-specific input)

The result is exposed both as a 0-10 severity score and as a
0-100 risk score so existing severity bucketing continues to
work while the dashboard can show the new "modern_risk_score"
value alongside the legacy ``csi_value``.

This module does not replace the legacy ``CalibratedSeverityModel``
- the calibrated ML output is still an *input* (the model's TP
probability) and the modern score blends it with the new
dimensions. The blend weights are config-driven.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import asdict, dataclass, field
from typing import Any

from src.intelligence.risk.asset_registry import AssetContext, AssetCriticalityService
from src.intelligence.risk.compensating_controls import CompensatingControlEngine
from src.intelligence.risk.cvss_v4 import score_finding_cvss_v4
from src.intelligence.risk.risk_acceptance import RiskAcceptanceManager

logger = logging.getLogger(__name__)


# Default weights for the modern composite. Exposed so configs and
# tests can override them. They sum to 1.0 by default.
DEFAULT_MODERN_WEIGHTS: dict[str, float] = {
    "cvss_v4": 0.22,
    "epss": 0.18,
    "kev": 0.08,
    "asset_criticality": 0.17,
    "business_multiplier": 0.10,
    "control_discount": 0.07,
    "chain_amplification": 0.10,
    "calibrated_tp": 0.08,
}

# Threat actor capability mapping - a 1-10 score for the kind of
# adversary expected to target the asset.
THREAT_ACTOR_LEVELS: dict[str, float] = {
    "unknown": 1.0,
    "script_kiddie": 2.0,
    "hacktivist": 4.0,
    "cybercrime": 6.0,
    "apt": 8.0,
    "nation_state": 10.0,
}


@dataclass
class ModernRiskInputs:
    """Inputs the modern risk score consumes."""

    cvss_v4_base: float = 0.0
    cvss_v4_threat_multiplier: float = 1.0
    epss_score: float = 0.0
    epss_percentile: float = 0.0
    in_cisa_kev: bool = False
    cisa_kev_due_offset_days: float = 0.0
    asset_criticality: float = 1.0
    business_multiplier: float = 1.0
    control_discount: float = 1.0
    attack_chain_weight: float = 0.0
    chain_amplification: float = 1.0
    calibrated_tp: float = 0.5
    threat_actor_capability: float = 1.0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ModernRiskScore:
    """The multi-dimensional risk output for a single finding."""

    modern_risk_score: float
    severity_score: float  # 0-10 legacy scale
    severity: str
    components: dict[str, float]
    weights: dict[str, float]
    asset_context: AssetContext | None
    finding_id: str = ""
    acceptance_suppressed: bool = False
    reason_codes: list[str] = field(default_factory=list)
    computed_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "modern_risk_score": round(self.modern_risk_score, 2),
            "severity_score": round(self.severity_score, 2),
            "severity": self.severity,
            "components": {k: round(v, 3) for k, v in self.components.items()},
            "weights": dict(self.weights),
            "asset_context": self.asset_context.to_dict() if self.asset_context else None,
            "finding_id": self.finding_id,
            "acceptance_suppressed": self.acceptance_suppressed,
            "reason_codes": list(self.reason_codes),
            "computed_at": self.computed_at,
        }


# ---------------------------------------------------------------------------
# Severity banding
# ---------------------------------------------------------------------------

SEVERITY_RANGES: tuple[tuple[float, str], ...] = (
    (8.8, "critical"),
    (6.8, "high"),
    (3.8, "medium"),
    (1.5, "low"),
    (0.0, "info"),
)


def _severity_from_score(score: float) -> str:
    for threshold, label in SEVERITY_RANGES:
        if score >= threshold:
            return label
    return "info"


# ---------------------------------------------------------------------------
# Calculator
# ---------------------------------------------------------------------------


class ModernRiskCalculator:
    """Compute a multi-dimensional risk score for a finding."""

    def __init__(
        self,
        *,
        weights: dict[str, float] | None = None,
        asset_service: AssetCriticalityService | None = None,
        control_engine: CompensatingControlEngine | None = None,
        acceptance_manager: RiskAcceptanceManager | None = None,
        threat_actor_levels: dict[str, float] | None = None,
    ) -> None:
        self.weights = dict(weights or DEFAULT_MODERN_WEIGHTS)
        self.asset_service = asset_service or AssetCriticalityService()
        self.control_engine = control_engine or CompensatingControlEngine()
        self.acceptance_manager = acceptance_manager or RiskAcceptanceManager()
        self.threat_actor_levels = dict(threat_actor_levels or THREAT_ACTOR_LEVELS)

    # -- public --------------------------------------------------------

    def for_finding(
        self,
        finding: dict[str, Any],
        *,
        host_or_url: str = "",
        target_info: dict[str, Any] | None = None,
        business_context: dict[str, Any] | None = None,
        chain_amplification: float = 1.0,
    ) -> ModernRiskScore:
        inputs = self.build_inputs(
            finding,
            host_or_url=host_or_url,
            target_info=target_info,
            business_context=business_context,
            chain_amplification=chain_amplification,
        )
        return self.compute(inputs, finding=finding, host_or_url=host_or_url)

    def build_inputs(
        self,
        finding: dict[str, Any],
        *,
        host_or_url: str = "",
        target_info: dict[str, Any] | None = None,
        business_context: dict[str, Any] | None = None,
        chain_amplification: float = 1.0,
    ) -> ModernRiskInputs:
        target_info = target_info or {}
        business_context = business_context or {}

        # Asset context first - everything downstream depends on it.
        asset_context = self.asset_service.resolve(
            host_or_url or finding.get("host") or finding.get("url") or "",
            target_info=target_info,
            business_context=business_context,
        )

        # CVSS v4 (compute on the fly if not present).
        cvss_v4_base = _extract_cvss_v4_base(finding)
        threat_multiplier = _extract_cvss_v4_threat_multiplier(finding)
        if cvss_v4_base <= 0.0:
            category = str(finding.get("category", "")).strip().lower()
            if category:
                evidence = finding.get("evidence") or {}
                threat_intel = finding.get("threat_intel") or {}
                score = score_finding_cvss_v4(
                    category,
                    evidence=evidence,
                    exploit_maturity=str(threat_intel.get("exploit_maturity", "X")),
                    epss_score=_epss_score(finding),
                    in_cisa_kev=bool(threat_intel.get("cisa_kev")),
                )
                cvss_v4_base = score.base_score
                threat_multiplier = score.threat_intel_multiplier

        # Threat intel
        epss = _epss_score(finding)
        epss_pct = _epss_percentile(finding)
        kev_flag = _kev_flag(finding)
        kev_offset = _kev_due_offset_days(finding)

        # Controls
        finding_id = str(finding.get("id") or finding.get("finding_id") or "")
        control_discount = self.control_engine.combined_discount(finding_id)

        # Chain
        chain_weight = _chain_weight(finding)
        amplification = _clamp(chain_amplification, 1.0, 3.0)

        # Calibrated model TP probability (from severity_model metadata)
        calibrated_tp = _calibrated_tp(finding)

        # Threat actor capability
        threat_actor_capability = _threat_actor_capability(
            finding, target_info, self.threat_actor_levels
        )

        return ModernRiskInputs(
            cvss_v4_base=cvss_v4_base,
            cvss_v4_threat_multiplier=threat_multiplier,
            epss_score=epss,
            epss_percentile=epss_pct,
            in_cisa_kev=kev_flag,
            cisa_kev_due_offset_days=kev_offset,
            asset_criticality=asset_context.criticality_score,
            business_multiplier=asset_context.business_multiplier,
            control_discount=control_discount,
            attack_chain_weight=chain_weight,
            chain_amplification=amplification,
            calibrated_tp=calibrated_tp,
            threat_actor_capability=threat_actor_capability,
        )

    def compute(
        self,
        inputs: ModernRiskInputs,
        *,
        finding: dict[str, Any] | None = None,
        host_or_url: str = "",
    ) -> ModernRiskScore:
        finding = finding or {}
        # Resolve asset context again only to retain the user-facing
        # information. We pass the asset criticality from ``inputs``
        # to keep the calculation pure.
        asset_context = self.asset_service.resolve(
            host_or_url or finding.get("host") or finding.get("url") or "",
            target_info=finding.get("target_info") or {},
        )

        # ---- 1. Component scores (each on 0-10 scale) -----------------
        cvss_v4_component = _clamp(inputs.cvss_v4_base, 0.0, 10.0)
        epss_component = _clamp(inputs.epss_score, 0.0, 1.0) * 10.0
        kev_component = 10.0 if inputs.in_cisa_kev else 0.0
        if inputs.in_cisa_kev and inputs.cisa_kev_due_offset_days < 0:
            # Past the CISA-mandated remediation deadline.
            kev_component = min(10.0, kev_component + 1.0)
        asset_component = _clamp(inputs.asset_criticality, 0.0, 10.0)
        business_component = _clamp((inputs.business_multiplier - 1.0) * 4.0 + 5.0, 0.0, 10.0)
        # Control discount reduces residual; if the discount is 0.4
        # we report 6.0 (a moderate residual) so a 10/10 finding on
        # an asset with a strong WAF doesn't fully drop to 0.
        control_component = _clamp(10.0 - inputs.control_discount * 10.0, 0.0, 10.0)
        chain_component = _clamp(inputs.attack_chain_weight * 2.0, 0.0, 10.0)
        calibrated_component = _clamp(inputs.calibrated_tp, 0.0, 1.0) * 10.0
        actor_component = _clamp(inputs.threat_actor_capability, 0.0, 10.0)

        # Threat actor capability is a small modifier on top of the
        # base composite (0% to 30% uplift) rather than a free
        # component, because it should never *reduce* a score.
        actor_uplift = actor_component / 33.33  # 0.0 - 0.30

        # ---- 2. Weighted blend (0-10 base) ---------------------------
        weights = dict(self.weights)
        total_weight = sum(weights.values()) or 1.0
        blended = (
            weights["cvss_v4"] * cvss_v4_component
            + weights["epss"] * epss_component
            + weights["kev"] * kev_component
            + weights["asset_criticality"] * asset_component
            + weights["business_multiplier"] * business_component
            + weights["control_discount"] * control_component
            + weights["chain_amplification"] * chain_component
            + weights["calibrated_tp"] * calibrated_component
        ) / total_weight

        # ---- 3. Apply non-multiplicative effects ---------------------
        # Attack chain amplification (multiplicative, capped 1.0-3.0)
        amplified = blended * _clamp(inputs.chain_amplification, 1.0, 3.0)
        # Threat actor uplift
        amplified = amplified * (1.0 + actor_uplift)
        # CVSS v4 threat multiplier is independent of the blended CVSS
        # component so it doesn't double-count.
        amplified = amplified * _clamp(inputs.cvss_v4_threat_multiplier, 1.0, 1.4)

        severity_score = _clamp(amplified, 0.0, 10.0)
        modern_risk = severity_score * 10.0  # scale to 0-100

        # Acceptance suppression
        finding_id = str(finding.get("id") or finding.get("finding_id") or "")
        acceptance_suppressed = False
        if finding_id:
            factor = self.acceptance_manager.suppression_factor(finding_id)
            if factor <= 0.0:
                modern_risk = 0.0
                acceptance_suppressed = True

        components = {
            "cvss_v4": cvss_v4_component,
            "epss": epss_component,
            "kev": kev_component,
            "asset_criticality": asset_component,
            "business_multiplier": business_component,
            "control_discount": control_component,
            "chain_amplification": chain_component,
            "calibrated_tp": calibrated_component,
            "threat_actor_capability": actor_component,
        }

        return ModernRiskScore(
            modern_risk_score=round(modern_risk, 2),
            severity_score=round(severity_score, 2),
            severity=_severity_from_score(severity_score),
            components=components,
            weights=weights,
            asset_context=asset_context,
            finding_id=finding_id,
            acceptance_suppressed=acceptance_suppressed,
            reason_codes=_build_reason_codes(inputs, asset_context),
            computed_at=time.time(),
        )

    def annotate_finding(
        self,
        finding: dict[str, Any],
        *,
        host_or_url: str = "",
        target_info: dict[str, Any] | None = None,
        business_context: dict[str, Any] | None = None,
        chain_amplification: float = 1.0,
    ) -> dict[str, Any]:
        score = self.for_finding(
            finding,
            host_or_url=host_or_url,
            target_info=target_info,
            business_context=business_context,
            chain_amplification=chain_amplification,
        )
        finding = dict(finding)
        finding["modern_risk_score"] = score.modern_risk_score
        finding["modern_risk_components"] = score.components
        finding["modern_risk_weights"] = score.weights
        finding["modern_risk_reasons"] = score.reason_codes
        finding["modern_risk_asset_context"] = (
            score.asset_context.to_dict() if score.asset_context else None
        )
        # Update severity/severity_score to the modern value while
        # keeping the legacy ``csi_value`` for backward compatibility.
        finding["severity"] = score.severity
        finding["severity_score"] = score.severity_score
        finding["asset_criticality_score"] = (
            score.asset_context.criticality_score if score.asset_context else 1.0
        )
        finding["business_multiplier"] = (
            score.asset_context.business_multiplier if score.asset_context else 1.0
        )
        finding["control_discount"] = (
            score.asset_context.control_discount if score.asset_context else 1.0
        )
        return finding


# ---------------------------------------------------------------------------
# Helpers / extraction utilities
# ---------------------------------------------------------------------------


def _clamp(value: float, low: float, high: float) -> float:
    return max(low, min(high, float(value)))


def _epss_score(finding: dict[str, Any]) -> float:
    threat_intel = finding.get("threat_intel") or {}
    raw = threat_intel.get("epss_score")
    if raw is None:
        raw = finding.get("epss_score")
    if raw is None:
        return 0.0
    try:
        return _clamp(float(raw), 0.0, 1.0)
    except (TypeError, ValueError):
        return 0.0


def _epss_percentile(finding: dict[str, Any]) -> float:
    threat_intel = finding.get("threat_intel") or {}
    raw = threat_intel.get("epss_percentile")
    if raw is None:
        raw = finding.get("epss_percentile")
    if raw is None:
        return 0.0
    try:
        return _clamp(float(raw), 0.0, 1.0)
    except (TypeError, ValueError):
        return 0.0


def _kev_flag(finding: dict[str, Any]) -> bool:
    threat_intel = finding.get("threat_intel") or {}
    return bool(threat_intel.get("cisa_kev") or finding.get("cisa_kev"))


def _kev_due_offset_days(finding: dict[str, Any]) -> float:
    threat_intel = finding.get("threat_intel") or {}
    due_ts = threat_intel.get("cisa_kev_due_ts")
    if not due_ts:
        return 0.0
    try:
        offset_seconds = float(due_ts) - time.time()
        return offset_seconds / 86400.0
    except (TypeError, ValueError):
        return 0.0


def _chain_weight(finding: dict[str, Any]) -> float:
    raw = finding.get("attack_chain_weight")
    if raw is None:
        attack_chains = finding.get("attack_chains") or []
        if attack_chains:
            # Map chain severity to a weight
            mapping = {"critical": 2.5, "high": 2.0, "medium": 1.25, "low": 0.5}
            weights = []
            for chain in attack_chains:
                severity = (
                    str(getattr(chain, "severity", None) or chain.get("severity", "")).lower()
                    if isinstance(chain, dict) or hasattr(chain, "severity")
                    else ""
                )
                if not severity:
                    continue
                weights.append(mapping.get(severity, 1.0))
            return max(weights) if weights else 0.0
        return 0.0
    try:
        return _clamp(float(raw), 0.0, 2.5)
    except (TypeError, ValueError):
        return 0.0


def _calibrated_tp(finding: dict[str, Any]) -> float:
    raw = finding.get("true_positive_probability")
    if raw is None:
        model = finding.get("severity_model") or {}
        raw = model.get("true_positive_probability")
    if raw is None:
        return 0.5
    try:
        return _clamp(float(raw), 0.0, 1.0)
    except (TypeError, ValueError):
        return 0.5


def _threat_actor_capability(
    finding: dict[str, Any],
    target_info: dict[str, Any] | None,
    levels: dict[str, float],
) -> float:
    target_info = target_info or {}
    actor = finding.get("threat_actor") or target_info.get("threat_actor") or "unknown"
    actor = str(actor).strip().lower()
    if actor in levels:
        return levels[actor]
    # Allow numeric input (1-10).
    try:
        return _clamp(float(actor), 0.0, 10.0)
    except (TypeError, ValueError):
        return levels.get("unknown", 1.0)


def _extract_cvss_v4_base(finding: dict[str, Any]) -> float:
    raw = finding.get("cvss_v4_score")
    if raw is None:
        block = finding.get("cvss_v4") or {}
        raw = block.get("base_score") if isinstance(block, dict) else None
    if raw is None:
        return 0.0
    try:
        return _clamp(float(raw), 0.0, 10.0)
    except (TypeError, ValueError):
        return 0.0


def _extract_cvss_v4_threat_multiplier(finding: dict[str, Any]) -> float:
    raw = finding.get("cvss_v4_threat_intel_multiplier")
    if raw is None:
        block = finding.get("cvss_v4") or {}
        raw = block.get("threat_intel_multiplier") if isinstance(block, dict) else None
    if raw is None:
        return 1.0
    try:
        return _clamp(float(raw), 1.0, 1.4)
    except (TypeError, ValueError):
        return 1.0


def _build_reason_codes(inputs: ModernRiskInputs, asset_context: AssetContext | None) -> list[str]:
    codes: list[str] = []
    if inputs.cvss_v4_base >= 9.0:
        codes.append("critical_cvss_v4")
    if inputs.in_cisa_kev:
        codes.append("cisa_kev")
    if inputs.epss_score >= 0.5:
        codes.append("epss_high")
    elif inputs.epss_score >= 0.1:
        codes.append("epss_medium")
    if inputs.asset_criticality >= 8.0:
        codes.append("crown_jewel_asset")
    if asset_context and asset_context.entity_type in {
        "payment_processor",
        "pii_store",
    }:
        codes.append(f"entity_{asset_context.entity_type}")
    if inputs.control_discount < 0.7:
        codes.append("control_mitigated")
    if inputs.attack_chain_weight > 0:
        codes.append("in_attack_chain")
    if inputs.threat_actor_capability >= 6.0:
        codes.append("advanced_adversary")
    return codes


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_default_lock = threading.Lock()
_default_calculator: ModernRiskCalculator | None = None


def get_default_modern_risk_calculator() -> ModernRiskCalculator:
    global _default_calculator
    with _default_lock:
        if _default_calculator is None:
            _default_calculator = ModernRiskCalculator()
        return _default_calculator


def reset_default_modern_risk_calculator() -> None:
    global _default_calculator
    with _default_lock:
        _default_calculator = None


__all__ = [
    "DEFAULT_MODERN_WEIGHTS",
    "ModernRiskCalculator",
    "ModernRiskInputs",
    "ModernRiskScore",
    "SEVERITY_RANGES",
    "THREAT_ACTOR_LEVELS",
    "get_default_modern_risk_calculator",
    "reset_default_modern_risk_calculator",
]
