"""Contracts and protocols for formal ExecutionRequest, Authorization, Scheduling, and Worker handoff."""

from __future__ import annotations

import time
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable


@dataclass(frozen=True, slots=True)
class ExecutionFinding:
    """Core contract for security findings emitted by execution."""

    category: str
    title: str
    url: str
    severity: str
    confidence: float
    score: int = 0
    evidence: tuple[tuple[str, Any], ...] = ()
    signals: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "title": self.title,
            "url": self.url,
            "severity": self.severity,
            "confidence": self.confidence,
            "score": self.score,
            "evidence": dict(self.evidence),
            "signals": list(self.signals),
        }

    def key(self) -> str:
        return f"{self.category}:{self.url}:{self.title or 'finding'}"

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> ExecutionFinding:
        ev = data.get("evidence")
        ev_tuple = tuple(ev.items()) if isinstance(ev, Mapping) else ()
        signals = tuple(str(s) for s in (data.get("signals") or []))
        return cls(
            category=str(data.get("category", "")),
            title=str(data.get("title", "")),
            url=str(data.get("url", "")),
            severity=str(data.get("severity", "info")).lower(),
            confidence=float(data.get("confidence", 0.5)),
            score=int(data.get("score", 0)),
            evidence=ev_tuple,
            signals=signals,
        )


@dataclass(frozen=True, slots=True)
class CandidateLease:
    """Strongly-typed lease token binding a candidate target to a specific execution, worker, and epoch."""

    candidate_id: str
    target_url: str
    execution_id: str
    lease_id: str
    worker_id: str
    expires_at: float
    epoch: int = 1
    partition_id: str = "P0"
    fencing_token: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "target_url": self.target_url,
            "execution_id": self.execution_id,
            "lease_id": self.lease_id,
            "worker_id": self.worker_id,
            "expires_at": self.expires_at,
            "epoch": self.epoch,
            "partition_id": self.partition_id,
            "fencing_token": self.fencing_token or f"{self.partition_id}:{self.epoch}:{self.lease_id}",
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
            epoch=int(data.get("epoch", 1)),
            partition_id=str(data.get("partition_id", "P0")),
            fencing_token=str(data.get("fencing_token", "")),
        )

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> CandidateLease:
        return cls.from_mapping(data)


@dataclass(frozen=True, slots=True)
class RawExecutionClaim:
    """Untrusted execution claim emitted by an isolated worker before control-plane verification."""

    request_id: str
    tenant_id: str
    candidate_id: str
    execution_id: str
    lease_id: str
    epoch: int
    worker_id: str
    outcome: str  # "COMPLETED", "FAILED", "TIMED_OUT", "REJECTED"
    duration_seconds: float
    findings: tuple[Any, ...] = ()
    state_deltas: tuple[tuple[str, Any], ...] = ()
    resource_consumption: tuple[tuple[str, Any], ...] = ()
    evidence_hashes: tuple[str, ...] = ()
    error: str = ""
    policy_version: str = ""
    ticket_nonce: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "tenant_id": self.tenant_id,
            "candidate_id": self.candidate_id,
            "execution_id": self.execution_id,
            "lease_id": self.lease_id,
            "epoch": self.epoch,
            "worker_id": self.worker_id,
            "outcome": self.outcome,
            "duration_seconds": round(self.duration_seconds, 3),
            "findings": [f.to_dict() if hasattr(f, "to_dict") else dict(f) for f in self.findings],
            "state_deltas": dict(self.state_deltas),
            "resource_consumption": dict(self.resource_consumption),
            "evidence_hashes": list(self.evidence_hashes),
            "error": self.error,
            "policy_version": self.policy_version,
            "ticket_nonce": self.ticket_nonce,
        }

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> RawExecutionClaim:
        raw_findings = data.get("findings") or []
        findings = tuple(
            ExecutionFinding.from_mapping(f) if isinstance(f, Mapping) else f for f in raw_findings
        )
        deltas = data.get("state_deltas") or {}
        deltas_tuple = tuple(deltas.items()) if isinstance(deltas, Mapping) else ()
        rc = data.get("resource_consumption") or {}
        rc_tuple = tuple(rc.items()) if isinstance(rc, Mapping) else ()
        ev = data.get("evidence_hashes") or ()
        return cls(
            request_id=str(data.get("request_id", "")),
            tenant_id=str(data.get("tenant_id", "default")),
            candidate_id=str(data.get("candidate_id", "")),
            execution_id=str(data.get("execution_id", "")),
            lease_id=str(data.get("lease_id", "")),
            epoch=int(data.get("epoch", 1)),
            worker_id=str(data.get("worker_id", "")),
            outcome=str(data.get("outcome", "COMPLETED")).upper(),
            duration_seconds=float(data.get("duration_seconds", 0.0)),
            findings=findings,
            state_deltas=deltas_tuple,
            resource_consumption=rc_tuple,
            evidence_hashes=tuple(ev),
            error=str(data.get("error", "")),
            policy_version=str(data.get("policy_version", "")),
            ticket_nonce=str(data.get("ticket_nonce", "")),
        )

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> RawExecutionClaim:
        return cls.from_mapping(data)


@dataclass(frozen=True, slots=True)
class ExecutionResultContract:
    """Formal outcome returned by Execution Worker."""

    request_id: str
    tenant_id: str
    outcome: str  # "COMPLETED", "FAILED", "TIMED_OUT", "REJECTED", "SKIPPED"
    duration_seconds: float = 0.0
    findings: tuple[Any, ...] = ()
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
            "findings": [f.to_dict() if hasattr(f, "to_dict") else dict(f) for f in self.findings],
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
    def from_mapping(cls, data: Mapping[str, Any]) -> ExecutionResultContract:
        raw_findings = data.get("findings") or []
        findings = tuple(
            ExecutionFinding.from_mapping(f) if isinstance(f, Mapping) else f for f in raw_findings
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
    def from_dict(cls, data: Mapping[str, Any]) -> ExecutionResultContract:
        return cls.from_mapping(data)


@runtime_checkable
class ExecutionRequestProtocol(Protocol):
    """Protocol representing an immutable contract of intent for execution."""

    request_id: str
    tenant_id: str
    stage: str
    deadline: float

    def to_dict(self) -> dict[str, Any]:
        ...


@runtime_checkable
class ExecutionResultProtocol(Protocol):
    """Protocol representing the outcome of an ExecutionRequest."""

    request_id: str
    tenant_id: str
    outcome: str
    duration_seconds: float
    error: str

    def to_dict(self) -> dict[str, Any]:
        ...


@runtime_checkable
class ExecutionAuthorizerProtocol(Protocol):
    """Protocol for validating scope and authorization before scheduling."""

    def authorize(self, request: Any) -> Any:
        ...


@runtime_checkable
class ExecutionSchedulerProtocol(Protocol):
    """Protocol for capacity and priority dispatching of authorized requests."""

    def schedule(self, ticket_or_request: Any) -> bool:
        ...


@runtime_checkable
class ExecutionWorkerProtocol(Protocol):
    """Protocol for stateless worker execution without decision rediscovery."""

    def execute(self, request: Any) -> Any:
        ...


__all__ = [
    "CandidateLease",
    "ExecutionAuthorizerProtocol",
    "ExecutionFinding",
    "ExecutionRequestProtocol",
    "ExecutionResultContract",
    "ExecutionResultProtocol",
    "ExecutionSchedulerProtocol",
    "ExecutionWorkerProtocol",
    "RawExecutionClaim",
]
