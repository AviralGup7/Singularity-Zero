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
import uuid
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



@dataclass(frozen=True, slots=True)
class TargetSpec:
    """Immutable target specification for execution."""

    host: str
    port: int = 443
    scheme: str = "https"
    path: str = "/"
    query_params: tuple[tuple[str, str], ...] = ()
    headers: tuple[tuple[str, str], ...] = ()

    @property
    def url(self) -> str:
        base = f"{self.scheme}://{self.host}"
        if (self.scheme == "https" and self.port != 443) or (self.scheme == "http" and self.port != 80):
            base = f"{base}:{self.port}"
        p = self.path if self.path.startswith("/") else f"/{self.path}"
        return f"{base}{p}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "port": self.port,
            "scheme": self.scheme,
            "path": self.path,
            "query_params": dict(self.query_params),
            "headers": dict(self.headers),
            "url": self.url,
        }

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any] | str | None) -> TargetSpec:
        if isinstance(data, str):
            from urllib.parse import urlparse
            parsed = urlparse(data if "://" in data else f"https://{data}")
            host = parsed.hostname or data
            scheme = parsed.scheme or "https"
            port = parsed.port or (80 if scheme == "http" else 443)
            path = parsed.path or "/"
            return cls(host=host, port=port, scheme=scheme, path=path)
        if not data:
            return cls(host="")
        qp = data.get("query_params") or {}
        qp_tuple = tuple((str(k), str(v)) for k, v in qp.items()) if isinstance(qp, Mapping) else ()
        hdrs = data.get("headers") or {}
        hdrs_tuple = tuple((str(k), str(v)) for k, v in hdrs.items()) if isinstance(hdrs, Mapping) else ()
        return cls(
            host=str(data.get("host", "")),
            port=int(data.get("port", 443)),
            scheme=str(data.get("scheme", "https")),
            path=str(data.get("path", "/")),
            query_params=qp_tuple,
            headers=hdrs_tuple,
        )

    @classmethod
    def from_dict(cls, data: Mapping[str, Any] | str | None) -> TargetSpec:
        return cls.from_mapping(data)


@dataclass(frozen=True, slots=True)
class ActionSpec:
    """Immutable single executable action specification."""

    action_id: str
    action_type: str  # "probe", "exploit", "mutate", "fingerprint", "nuclei"
    tool_or_detector: str
    payload: tuple[tuple[str, Any], ...] = ()
    priority: int = 100
    max_retries: int = 3

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_id": self.action_id,
            "action_type": self.action_type,
            "tool_or_detector": self.tool_or_detector,
            "payload": dict(self.payload),
            "priority": self.priority,
            "max_retries": self.max_retries,
        }

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> ActionSpec:
        payload = data.get("payload") or {}
        payload_tuple = tuple(payload.items()) if isinstance(payload, Mapping) else ()
        return cls(
            action_id=str(data.get("action_id") or uuid.uuid4().hex[:12]),
            action_type=str(data.get("action_type", "probe")),
            tool_or_detector=str(data.get("tool_or_detector", "")),
            payload=payload_tuple,
            priority=int(data.get("priority", 100)),
            max_retries=int(data.get("max_retries", 3)),
        )

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ActionSpec:
        return cls.from_mapping(data)


@dataclass(frozen=True, slots=True)
class ResourceLimits:
    """Immutable resource boundaries and quotas for execution."""

    timeout_seconds: float = 300.0
    max_memory_mb: int = 512
    max_concurrency: int = 4
    max_bandwidth_kbps: int = 0
    max_payload_bytes: int = 1_048_576

    def to_dict(self) -> dict[str, Any]:
        return {
            "timeout_seconds": self.timeout_seconds,
            "max_memory_mb": self.max_memory_mb,
            "max_concurrency": self.max_concurrency,
            "max_bandwidth_kbps": self.max_bandwidth_kbps,
            "max_payload_bytes": self.max_payload_bytes,
        }

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any] | None) -> ResourceLimits:
        if not data:
            return cls()
        return cls(
            timeout_seconds=float(data.get("timeout_seconds", 300.0)),
            max_memory_mb=int(data.get("max_memory_mb", 512)),
            max_concurrency=int(data.get("max_concurrency", 4)),
            max_bandwidth_kbps=int(data.get("max_bandwidth_kbps", 0)),
            max_payload_bytes=int(data.get("max_payload_bytes", 1_048_576)),
        )

    @classmethod
    def from_dict(cls, data: Mapping[str, Any] | None) -> ResourceLimits:
        return cls.from_mapping(data)


@dataclass(frozen=True, slots=True)
class ScopeToken:
    """Immutable cryptographically verifiable scope assertion."""

    scope_hash: str
    allowed_domains: tuple[str, ...] = ()
    allowed_cidrs: tuple[str, ...] = ()
    forbidden_paths: tuple[str, ...] = ()
    issuer_signature: str = ""
    expires_at: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "scope_hash": self.scope_hash,
            "allowed_domains": list(self.allowed_domains),
            "allowed_cidrs": list(self.allowed_cidrs),
            "forbidden_paths": list(self.forbidden_paths),
            "issuer_signature": self.issuer_signature,
            "expires_at": self.expires_at,
        }

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any] | None) -> ScopeToken:
        if not data:
            return cls(scope_hash="")
        return cls(
            scope_hash=str(data.get("scope_hash", "")),
            allowed_domains=tuple(str(d) for d in (data.get("allowed_domains") or ())),
            allowed_cidrs=tuple(str(c) for c in (data.get("allowed_cidrs") or ())),
            forbidden_paths=tuple(str(p) for p in (data.get("forbidden_paths") or ())),
            issuer_signature=str(data.get("issuer_signature", "")),
            expires_at=float(data.get("expires_at", 0.0)),
        )

    @classmethod
    def from_dict(cls, data: Mapping[str, Any] | None) -> ScopeToken:
        return cls.from_mapping(data)


class PlacementStatus:
    """Outcomes from Actor Scheduler placement decisions."""

    LEASED = "LEASED"
    DEFERRED = "PLACEMENT_DEFERRED"
    REJECTED = "PLACEMENT_REJECTED"
    WORKER_UNAVAILABLE = "WORKER_UNAVAILABLE"
    CIRCUIT_OPEN = "CIRCUIT_OPEN"


@dataclass(frozen=True, slots=True)
class CandidateLease:
    """Strongly-typed lease token binding a candidate target to a specific execution and worker."""

    candidate_id: str
    target_url: str
    execution_id: str
    lease_id: str
    worker_id: str
    expires_at: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "target_url": self.target_url,
            "execution_id": self.execution_id,
            "lease_id": self.lease_id,
            "worker_id": self.worker_id,
            "expires_at": self.expires_at,
        }

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> CandidateLease:
        return cls(
            candidate_id=str(data.get("candidate_id", "")),
            target_url=str(data.get("target_url", "")),
            execution_id=str(data.get("execution_id", "")),
            lease_id=str(data.get("lease_id", "")),
            worker_id=str(data.get("worker_id", "")),
            expires_at=float(data.get("expires_at", 0.0)),
        )

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> CandidateLease:
        return cls.from_mapping(data)


@dataclass(frozen=True, slots=True)
class ExecutionRequest:
    """Formal contract of intent handed off from Decision to Execution."""

    request_id: str
    tenant_id: str
    target: TargetSpec
    stage: str
    actions: tuple[ActionSpec, ...] = ()
    resource_limits: ResourceLimits = field(default_factory=ResourceLimits)
    scope_token: ScopeToken = field(default_factory=lambda: ScopeToken(scope_hash=""))
    deadline: float = 0.0
    correlation_id: str = ""
    metadata: tuple[tuple[str, Any], ...] = ()
    execution_id: str = ""
    job_id: str = ""
    candidate_id: str = ""
    lease_id: str = ""
    policy_version: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "tenant_id": self.tenant_id,
            "target": self.target.to_dict(),
            "stage": self.stage,
            "actions": [a.to_dict() for a in self.actions],
            "resource_limits": self.resource_limits.to_dict(),
            "scope_token": self.scope_token.to_dict(),
            "deadline": self.deadline,
            "correlation_id": self.correlation_id,
            "metadata": dict(self.metadata),
            "execution_id": self.execution_id,
            "job_id": self.job_id,
            "candidate_id": self.candidate_id,
            "lease_id": self.lease_id,
            "policy_version": self.policy_version,
        }

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> ExecutionRequest:
        target_raw = data.get("target")
        target = TargetSpec.from_mapping(target_raw) if isinstance(target_raw, (Mapping, str)) else TargetSpec(host="")
        actions_raw = data.get("actions") or ()
        actions = tuple(
            ActionSpec.from_mapping(a) if isinstance(a, Mapping) else a for a in actions_raw
        )
        limits_raw = data.get("resource_limits")
        limits = ResourceLimits.from_mapping(limits_raw) if isinstance(limits_raw, Mapping) else ResourceLimits()
        scope_raw = data.get("scope_token")
        scope = ScopeToken.from_mapping(scope_raw) if isinstance(scope_raw, Mapping) else ScopeToken(scope_hash="")
        meta = data.get("metadata") or {}
        meta_tuple = tuple(meta.items()) if isinstance(meta, Mapping) else ()
        req_id = str(data.get("request_id") or uuid.uuid4().hex)
        return cls(
            request_id=req_id,
            tenant_id=str(data.get("tenant_id", "default")),
            target=target,
            stage=str(data.get("stage", "")),
            actions=actions,
            resource_limits=limits,
            scope_token=scope,
            deadline=float(data.get("deadline", 0.0)),
            correlation_id=str(data.get("correlation_id", "") or req_id),
            metadata=meta_tuple,
            execution_id=str(data.get("execution_id", "")),
            job_id=str(data.get("job_id", "")),
            candidate_id=str(data.get("candidate_id", "")),
            lease_id=str(data.get("lease_id", "")),
            policy_version=str(data.get("policy_version", "")),
        )

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ExecutionRequest:
        return cls.from_mapping(data)


@dataclass(frozen=True, slots=True)
class ExecutionResult:
    """Formal outcome returned by Execution Worker."""

    request_id: str
    tenant_id: str
    outcome: str  # "COMPLETED", "FAILED", "TIMED_OUT", "REJECTED", "SKIPPED"
    duration_seconds: float = 0.0
    findings: tuple[Finding, ...] = ()
    artifacts: tuple[tuple[str, Any], ...] = ()
    state_deltas: tuple[tuple[str, Any], ...] = ()
    resource_consumption: tuple[tuple[str, Any], ...] = ()
    error: str = ""
    execution_id: str = ""
    job_id: str = ""
    candidate_id: str = ""
    lease_id: str = ""
    policy_version: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "tenant_id": self.tenant_id,
            "outcome": self.outcome,
            "duration_seconds": round(self.duration_seconds, 3),
            "findings": [f.to_dict() for f in self.findings],
            "artifacts": dict(self.artifacts),
            "state_deltas": dict(self.state_deltas),
            "resource_consumption": dict(self.resource_consumption),
            "error": self.error,
            "execution_id": self.execution_id,
            "job_id": self.job_id,
            "candidate_id": self.candidate_id,
            "lease_id": self.lease_id,
            "policy_version": self.policy_version,
        }

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> ExecutionResult:
        raw_findings = data.get("findings") or []
        findings = tuple(
            Finding.from_mapping(f) if isinstance(f, Mapping) else f for f in raw_findings
        )
        artifacts = data.get("artifacts") or {}
        artifacts_tuple = tuple(artifacts.items()) if isinstance(artifacts, Mapping) else ()
        deltas = data.get("state_deltas") or {}
        deltas_tuple = tuple(deltas.items()) if isinstance(deltas, Mapping) else ()
        rc = data.get("resource_consumption") or {}
        rc_tuple = tuple(rc.items()) if isinstance(rc, Mapping) else ()
        return cls(
            request_id=str(data.get("request_id", "")),
            tenant_id=str(data.get("tenant_id", "default")),
            outcome=str(data.get("outcome", "COMPLETED")).upper(),
            duration_seconds=float(data.get("duration_seconds", 0.0)),
            findings=findings,
            artifacts=artifacts_tuple,
            state_deltas=deltas_tuple,
            resource_consumption=rc_tuple,
            error=str(data.get("error", "")),
            execution_id=str(data.get("execution_id", "")),
            job_id=str(data.get("job_id", "")),
            candidate_id=str(data.get("candidate_id", "")),
            lease_id=str(data.get("lease_id", "")),
            policy_version=str(data.get("policy_version", "")),
        )


    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ExecutionResult:
        return cls.from_mapping(data)


__all__ = [
    "ActionSpec",
    "AttackPlan",
    "AttackStep",
    "BudgetSnapshot",
    "CandidateLease",
    "ExecutionRequest",
    "ExecutionResult",
    "Finding",
    "FindingDecision",
    "PlacementStatus",
    "ResourceLimits",
    "ScanPlan",
    "ScanResult",
    "ScanTarget",
    "ScopeToken",
    "StageRequest",
    "StageResult",
    "TargetSpec",
]

