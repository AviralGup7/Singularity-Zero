"""Immutable, strongly-typed domain models and result objects for the decision subsystem.

Provides frozen, memory-efficient data structures with dictionary serialization
and deserialization support for backward compatibility:
- ScanTarget
- ScanPlan
- AttackStep & AttackPlan
- ScanResult
- Finding
- FindingDecision
- BudgetSnapshot
- StageRequest
- StageResult
"""

from __future__ import annotations

import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class FindingDecision:
    """Immutable classification decision for a security finding."""

    decision: str  # "HIGH", "MEDIUM", "LOW", "DROP"
    reason: str = ""
    confidence_factors: tuple[tuple[str, Any], ...] = ()
    diff_score: int = 0
    diff_classification: str = ""
    suppress_reason: str = ""
    thresholds_used: tuple[tuple[str, float], ...] = ()
    reportable: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision,
            "reason": self.reason,
            "confidence_factors": dict(self.confidence_factors),
            "diff_score": self.diff_score,
            "diff_classification": self.diff_classification,
            "suppress_reason": self.suppress_reason,
            "thresholds_used": dict(self.thresholds_used),
            "reportable": self.reportable,
        }

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any] | None) -> FindingDecision:
        if not data:
            return cls(decision="DROP", reportable=False)
        cf = data.get("confidence_factors")
        cf_tuple = tuple(cf.items()) if isinstance(cf, Mapping) else ()
        tu = data.get("thresholds_used")
        tu_tuple = tuple(tu.items()) if isinstance(tu, Mapping) else ()
        decision = str(data.get("decision", "DROP")).upper()
        reportable = data.get("reportable", decision != "DROP")
        return cls(
            decision=decision,
            reason=str(data.get("reason", "")),
            confidence_factors=cf_tuple,
            diff_score=int(data.get("diff_score", 0)),
            diff_classification=str(data.get("diff_classification", "")),
            suppress_reason=str(data.get("suppress_reason", "")),
            thresholds_used=tu_tuple,
            reportable=bool(reportable),
        )

    @classmethod
    def from_dict(cls, data: Mapping[str, Any] | None) -> FindingDecision:
        return cls.from_mapping(data)


@dataclass(frozen=True, slots=True)
class AttackStep:
    """Immutable single step within a compound validation plan."""

    order: int
    action: str
    goal: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "order": self.order,
            "action": self.action,
            "goal": self.goal,
        }

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> AttackStep:
        return cls(
            order=int(data.get("order", 1)),
            action=str(data.get("action", "")),
            goal=str(data.get("goal", "")),
        )


@dataclass(frozen=True, slots=True)
class AttackPlan:
    """Immutable multi-step compound attack and validation plan."""

    rule_id: str
    score: int
    reason: str
    prerequisites: tuple[str, ...] = ()
    required_sessions: tuple[str, ...] = ()
    stop_conditions: tuple[str, ...] = ()
    steps: tuple[AttackStep, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "score": self.score,
            "reason": self.reason,
            "prerequisites": list(self.prerequisites),
            "required_sessions": list(self.required_sessions),
            "stop_conditions": list(self.stop_conditions),
            "steps": [step.to_dict() for step in self.steps],
        }

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any] | None) -> AttackPlan:
        if not data:
            return cls(rule_id="", score=0, reason="")
        raw_steps = data.get("steps") or []
        steps = tuple(
            AttackStep.from_mapping(s) if isinstance(s, Mapping) else s for s in raw_steps
        )
        return cls(
            rule_id=str(data.get("rule_id", "")),
            score=int(data.get("score", 0)),
            reason=str(data.get("reason", "")),
            prerequisites=tuple(str(x) for x in data.get("prerequisites", [])),
            required_sessions=tuple(str(x) for x in data.get("required_sessions", [])),
            stop_conditions=tuple(str(x) for x in data.get("stop_conditions", [])),
            steps=steps,
        )

    @classmethod
    def from_dict(cls, data: Mapping[str, Any] | None) -> AttackPlan:
        return cls.from_mapping(data)


@dataclass(frozen=True, slots=True)
class Finding:
    """Immutable security finding item."""

    category: str
    title: str
    url: str
    severity: str
    confidence: float
    score: int = 0
    evidence: tuple[tuple[str, Any], ...] = ()
    signals: tuple[str, ...] = ()
    decision: FindingDecision | None = None
    validation_actions: tuple[tuple[str, Any], ...] = ()

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "category": self.category,
            "title": self.title,
            "url": self.url,
            "severity": self.severity,
            "confidence": self.confidence,
            "score": self.score,
            "evidence": dict(self.evidence),
            "signals": list(self.signals),
        }
        if self.decision is not None:
            result["decision"] = self.decision.to_dict()
        if self.validation_actions:
            result["validation_actions"] = [
                dict(action) if isinstance(action, tuple) else action
                for action in self.validation_actions
            ]
        return result

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> Finding:
        ev = data.get("evidence")
        ev_tuple = tuple(ev.items()) if isinstance(ev, Mapping) else ()
        signals = tuple(str(s) for s in (data.get("signals") or []))
        raw_decision = data.get("decision")
        decision_obj = (
            FindingDecision.from_mapping(raw_decision)
            if isinstance(raw_decision, Mapping)
            else None
        )
        return cls(
            category=str(data.get("category", "")),
            title=str(data.get("title", "")),
            url=str(data.get("url", "")),
            severity=str(data.get("severity", "info")).lower(),
            confidence=float(data.get("confidence", 0.5)),
            score=int(data.get("score", 0)),
            evidence=ev_tuple,
            signals=signals,
            decision=decision_obj,
        )

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Finding:
        return cls.from_mapping(data)


@dataclass(frozen=True, slots=True)
class ScanResult:
    """Immutable outcome of scanning a single target."""

    target: str
    success: bool
    findings: tuple[Finding, ...] = ()
    duration_ms: float = 0.0
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "success": self.success,
            "findings": [f.to_dict() for f in self.findings],
            "duration_ms": self.duration_ms,
            "error": self.error,
        }

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> ScanResult:
        raw_findings = data.get("findings") or []
        findings = tuple(
            Finding.from_mapping(f) if isinstance(f, Mapping) else f for f in raw_findings
        )
        return cls(
            target=str(data.get("target", "")),
            success=bool(data.get("success", False)),
            findings=findings,
            duration_ms=float(data.get("duration_ms", 0.0)),
            error=str(data.get("error", "")),
        )

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ScanResult:
        return cls.from_mapping(data)


@dataclass(frozen=True, slots=True)
class BudgetSnapshot:
    """Immutable point-in-time snapshot of the hunt budget state."""

    elapsed_seconds: float
    requests_emitted: int
    productive_findings: int
    high_confidence_findings: int = 0
    exhausted_axes: tuple[str, ...] = ()
    terminated_early: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "elapsed_seconds": round(self.elapsed_seconds, 3),
            "requests_emitted": self.requests_emitted,
            "productive_findings": self.productive_findings,
            "high_confidence_findings": self.high_confidence_findings,
            "exhausted_axes": list(self.exhausted_axes),
            "terminated_early": self.terminated_early,
        }

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> BudgetSnapshot:
        axes = tuple(str(a) for a in data.get("exhausted_axes", []))
        return cls(
            elapsed_seconds=float(data.get("elapsed_seconds", 0.0)),
            requests_emitted=int(data.get("requests_emitted", 0)),
            productive_findings=int(data.get("productive_findings", 0)),
            high_confidence_findings=int(data.get("high_confidence_findings", 0)),
            exhausted_axes=axes,
            terminated_early=bool(data.get("terminated_early", False)),
        )

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> BudgetSnapshot:
        return cls.from_mapping(data)


@dataclass(frozen=True, slots=True)
class ScanPlan:
    """Immutable plan specification for target scanning."""

    targets: tuple[str, ...]
    batch_size: int = 50
    concurrency: int = 10
    boost_on_findings: bool = True
    early_terminate: bool = True
    early_terminate_min: int = 5
    early_terminate_ratio: float = 0.3
    boost_factor: float = 2.0
    max_batches: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "targets": list(self.targets),
            "batch_size": self.batch_size,
            "concurrency": self.concurrency,
            "boost_on_findings": self.boost_on_findings,
            "early_terminate": self.early_terminate,
            "early_terminate_min": self.early_terminate_min,
            "early_terminate_ratio": self.early_terminate_ratio,
            "boost_factor": self.boost_factor,
            "max_batches": self.max_batches,
        }

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> ScanPlan:
        targets = tuple(str(u) for u in (data.get("targets") or data.get("urls") or []))
        return cls(
            targets=targets,
            batch_size=int(data.get("batch_size", 50)),
            concurrency=int(data.get("concurrency", 10)),
            boost_on_findings=bool(data.get("boost_on_findings", True)),
            early_terminate=bool(data.get("early_terminate", True)),
            early_terminate_min=int(data.get("early_terminate_min", 5)),
            early_terminate_ratio=float(data.get("early_terminate_ratio", 0.3)),
            boost_factor=float(data.get("boost_factor", 2.0)),
            max_batches=int(data["max_batches"]) if data.get("max_batches") is not None else None,
        )

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ScanPlan:
        return cls.from_mapping(data)


@dataclass(frozen=True, slots=True)
class ScanTarget:
    """Immutable snapshot descriptor of a scan target."""

    url: str
    base_priority: float = 0.0
    current_priority: float = 0.0
    effective_priority: float = 0.0
    bid_score: float = 0.0
    findings_count: int = 0
    boost_factors: tuple[str, ...] = ()
    scanned: bool = False
    created_at: float = field(default_factory=time.time)
    last_boosted_at: float | None = None
    metadata: tuple[tuple[str, Any], ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "base_priority": round(self.base_priority, 2),
            "current_priority": round(self.current_priority, 2),
            "effective_priority": round(self.effective_priority, 2),
            "bid_score": round(self.bid_score, 3),
            "findings_count": self.findings_count,
            "boost_factors": list(self.boost_factors),
            "scanned": self.scanned,
            "created_at": self.created_at,
            "last_boosted_at": self.last_boosted_at,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> ScanTarget:
        md = data.get("metadata")
        md_tuple = tuple(md.items()) if isinstance(md, Mapping) else ()
        boosts = tuple(str(b) for b in (data.get("boost_factors") or data.get("boosts") or []))
        return cls(
            url=str(data.get("url", "")),
            base_priority=float(data.get("base_priority", 0.0)),
            current_priority=float(data.get("current_priority", 0.0)),
            effective_priority=float(data.get("effective_priority", data.get("current_priority", 0.0))),
            bid_score=float(data.get("bid_score", 0.0)),
            findings_count=int(data.get("findings_count", 0)),
            boost_factors=boosts,
            scanned=bool(data.get("scanned", False)),
            created_at=float(data.get("created_at", time.time())),
            last_boosted_at=float(data["last_boosted_at"]) if data.get("last_boosted_at") is not None else None,
            metadata=md_tuple,
        )

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ScanTarget:
        return cls.from_mapping(data)


@dataclass(frozen=True, slots=True)
class StageRequest:
    """Immutable specification for stage execution."""

    stage_name: str
    targets: tuple[str, ...] = ()
    parameters: tuple[tuple[str, Any], ...] = ()
    timeout_seconds: float = 300.0
    context_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "stage_name": self.stage_name,
            "targets": list(self.targets),
            "parameters": dict(self.parameters),
            "timeout_seconds": self.timeout_seconds,
            "context_id": self.context_id,
        }

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> StageRequest:
        params = data.get("parameters") or {}
        params_tuple = tuple(params.items()) if isinstance(params, Mapping) else ()
        targets = tuple(str(t) for t in (data.get("targets") or []))
        return cls(
            stage_name=str(data.get("stage_name", "")),
            targets=targets,
            parameters=params_tuple,
            timeout_seconds=float(data.get("timeout_seconds", 300.0)),
            context_id=str(data.get("context_id", "")),
        )

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> StageRequest:
        return cls.from_mapping(data)


@dataclass(frozen=True, slots=True)
class StageResult:
    """Immutable result outcome of a stage run."""

    stage_name: str
    outcome: str  # "completed", "failed", "skipped"
    duration_seconds: float
    metrics: tuple[tuple[str, Any], ...] = ()
    findings: tuple[Finding, ...] = ()
    state_delta: tuple[tuple[str, Any], ...] = ()
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "stage_name": self.stage_name,
            "outcome": self.outcome,
            "duration_seconds": round(self.duration_seconds, 2),
            "metrics": dict(self.metrics),
            "findings": [f.to_dict() for f in self.findings],
            "state_delta": dict(self.state_delta),
            "error": self.error,
        }

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> StageResult:
        metrics = data.get("metrics") or {}
        metrics_tuple = tuple(metrics.items()) if isinstance(metrics, Mapping) else ()
        delta = data.get("state_delta") or {}
        delta_tuple = tuple(delta.items()) if isinstance(delta, Mapping) else ()
        raw_findings = data.get("findings") or data.get("active_scan_findings") or []
        findings = tuple(
            Finding.from_mapping(f) if isinstance(f, Mapping) else f for f in raw_findings
        )
        return cls(
            stage_name=str(data.get("stage_name", "")),
            outcome=str(data.get("outcome", "completed")),
            duration_seconds=float(data.get("duration_seconds", 0.0)),
            metrics=metrics_tuple,
            findings=findings,
            state_delta=delta_tuple,
            error=str(data.get("error", "")),
        )

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> StageResult:
        return cls.from_mapping(data)


__all__ = [
    "AttackPlan",
    "AttackStep",
    "BudgetSnapshot",
    "Finding",
    "FindingDecision",
    "ScanPlan",
    "ScanResult",
    "ScanTarget",
    "StageRequest",
    "StageResult",
]
