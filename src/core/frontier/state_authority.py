"""Authoritative state and settlement engine for the Cyber Security Test Pipeline.

Implements the single-commit StateAuthority (WAL -> CRDT -> Execution ID Commit)
and the SettlementCoordinator coordinating atomic budget, lease fencing, and state settlement.
"""

from __future__ import annotations

import logging
import threading
import time
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from src.core.contracts.execution_request import (
    CandidateLease,
    RawExecutionClaim,
)
from src.core.contracts.execution_request import (
    ExecutionFinding as Finding,
)
from src.core.contracts.execution_request import (
    ExecutionResultContract as ExecutionResult,
)
from src.core.contracts.pipeline_runtime import StageOutput
from src.core.frontier.causal_identity import (
    CausalIdentity,
    attempt_n_from_output,
    command_id_from_ctx,
    mint_causal_identity,
)
from src.core.frontier.state import NeuralState

logger = logging.getLogger(__name__)


def _to_mutable(value: Any) -> Any:
    """Deep-copy mappings/sequences so FrontierWAL can msgpack them.

    ``StageOutput`` freezes ``state_delta`` into ``MappingProxyType``;
    a shallow ``dict()`` leaves nested proxies and WAL append fails.
    """
    if isinstance(value, Mapping):
        return {k: _to_mutable(v) for k, v in value.items()}
    if isinstance(value, (tuple, list, set, frozenset)):
        return [_to_mutable(item) for item in value]
    return value


def _dict_findings_from_delta(state_delta: Mapping[str, Any] | None) -> tuple[dict[str, Any], ...]:
    """Extract mapping findings for EventBus projection. Non-mappings are dropped."""
    if not state_delta:
        return ()
    raw = state_delta.get("reportable_findings")
    if not isinstance(raw, (list, tuple)):
        raw = state_delta.get("findings")
    if not isinstance(raw, (list, tuple)):
        return ()
    findings: list[dict[str, Any]] = []
    for item in raw:
        if isinstance(item, dict):
            findings.append(dict(item))
        elif isinstance(item, Mapping) and not isinstance(item, (str, bytes)):
            findings.append(dict(item))
    return tuple(findings)


@dataclass(frozen=True, slots=True)
class SettlementResult:
    """Outcome of settling an ExecutionResult, RawExecutionClaim, or StageOutput."""

    execution_id: str
    status: str  # "COMMITTED", "DEDUPLICATED", "REJECTED"
    wal_id: str | None = None
    committed_findings_count: int = 0
    committed_deltas_count: int = 0
    error: str = ""
    committed_findings: tuple[dict[str, Any], ...] = ()
    command_id: str = ""
    attempt_id: str = ""
    settlement_id: str = ""
    event_ids: tuple[str, ...] = ()
    delivery_ids: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "execution_id": self.execution_id,
            "status": self.status,
            "wal_id": self.wal_id,
            "committed_findings_count": self.committed_findings_count,
            "committed_deltas_count": self.committed_deltas_count,
            "error": self.error,
            "committed_findings": list(self.committed_findings),
            "command_id": self.command_id,
            "attempt_id": self.attempt_id,
            "settlement_id": self.settlement_id,
            "event_ids": list(self.event_ids),
            "delivery_ids": list(self.delivery_ids),
        }

    def causal_identity(self) -> CausalIdentity | None:
        if not self.execution_id:
            return None
        try:
            return mint_causal_identity(
                execution_id=self.execution_id,
                command_id=self.command_id,
                attempt_id=self.attempt_id,
                settlement_id=self.settlement_id,
                wal_id=str(self.wal_id or ""),
            )
        except Exception:
            return None


class StateAuthority:
    """Single-source-of-truth State Merge & Durability Authority."""

    def __init__(
        self,
        state: NeuralState | None = None,
        wal: Any | None = None,
        cache: Any | None = None,
        auto_compact_interval: int = 500,
    ) -> None:
        self.state = state if state is not None else NeuralState()
        self.wal = wal
        self.cache = cache
        self.auto_compact_interval = auto_compact_interval
        self._append_count = 0
        self._committed_execution_ids: set[str] = set()
        self._committed_attempt_ids: set[str] = set()
        self._lock = threading.RLock()

    @property
    def committed_execution_ids(self) -> frozenset[str]:
        with self._lock:
            return frozenset(self._committed_execution_ids)

    def is_committed(self, execution_id: str) -> bool:
        if not execution_id:
            return False
        with self._lock:
            return execution_id in self._committed_execution_ids

    def is_attempt_committed(self, attempt_id: str) -> bool:
        if not attempt_id:
            return False
        with self._lock:
            return attempt_id in self._committed_attempt_ids

    def commit(
        self,
        result: ExecutionResult,
        stage_name: str = "execution",
    ) -> SettlementResult:
        """Durable, idempotent atomic commit of an ExecutionResult."""
        with self._lock:
            # 1. Deduplication Check
            if result.execution_id and result.execution_id in self._committed_execution_ids:
                logger.debug(
                    "StateAuthority: execution_id %s already committed — deduplicated",
                    result.execution_id,
                )
                return SettlementResult(
                    execution_id=result.execution_id,
                    status="DEDUPLICATED",
                    committed_findings_count=len(result.findings),
                    committed_deltas_count=len(result.state_deltas),
                )

            # Convert result findings and state deltas to a unified delta dictionary
            deltas_dict: dict[str, Any] = dict(result.state_deltas)
            if result.findings:
                finding_dicts = [f.to_dict() for f in result.findings]
                deltas_dict["findings"] = finding_dicts

            # 2. Schema / Delta Validation
            try:
                from src.core.contracts.state_schema import GLOBAL_STATE_SCHEMA_REGISTRY

                errors = GLOBAL_STATE_SCHEMA_REGISTRY.validate_delta(deltas_dict)
                if errors:
                    err_msg = f"Delta validation failed: {'; '.join(errors)}"
                    logger.error("StateAuthority: %s", err_msg)
                    return SettlementResult(
                        execution_id=result.execution_id,
                        status="REJECTED",
                        error=err_msg,
                    )
            except (ImportError, Exception) as exc:
                logger.debug("StateAuthority: Schema registry check skipped (%s)", exc)

            # 3. WAL Durable Append
            wal_id: str | None = None
            if self.wal is not None:
                try:
                    if hasattr(self.wal, "log_delta"):
                        wal_id = self.wal.log_delta(stage_name, deltas_dict)
                    elif hasattr(self.wal, "append"):
                        wal_id = self.wal.append(deltas_dict)
                except Exception as exc:
                    err_msg = f"WAL durability flush failed: {exc}"
                    logger.exception("StateAuthority: %s", err_msg)
                    return SettlementResult(
                        execution_id=result.execution_id,
                        status="REJECTED",
                        error=err_msg,
                    )

            if wal_id:
                deltas_dict["_wal_id"] = wal_id

            # 4. Deterministic CRDT Merge
            try:
                self.state.apply_delta(deltas_dict)
            except Exception as exc:
                err_msg = f"CRDT delta merge failed: {exc}"
                logger.exception("StateAuthority: %s", err_msg)
                return SettlementResult(
                    execution_id=result.execution_id,
                    status="REJECTED",
                    error=err_msg,
                )

            # 5. Commit Execution Identity
            if result.execution_id:
                self._committed_execution_ids.add(result.execution_id)

            # 6. Materialize into Cache if attached
            if self.cache is not None and hasattr(self.cache, "set"):
                try:
                    self.cache.set(f"state:snap:{stage_name}", self.state.get_snapshot())
                except Exception as exc:
                    logger.debug("StateAuthority: Cache materialization notice: %s", exc)

            return SettlementResult(
                execution_id=result.execution_id,
                status="COMMITTED",
                wal_id=wal_id,
                committed_findings_count=len(result.findings),
                committed_deltas_count=len(result.state_deltas),
            )

    def append_settlement_intent(self, intent: SettlementIntent) -> str:
        """Atomically append a SettlementIntent to the WAL (the single authoritative settlement point)."""
        with self._lock:
            if intent.attempt_id and intent.attempt_id in self._committed_attempt_ids:
                return "DEDUPLICATED"
            if intent.execution_id and intent.execution_id in self._committed_execution_ids:
                return "DEDUPLICATED"

            envelope = _to_mutable(intent.to_dict())
            wal_id: str | None = None
            if self.wal is not None:
                if hasattr(self.wal, "log_delta"):
                    wal_id = self.wal.log_delta(intent.stage_name, envelope)
                elif hasattr(self.wal, "append"):
                    wal_id = self.wal.append(envelope)
            else:
                wal_id = f"wal_{uuid.uuid4().hex[:8]}"

            if not wal_id:
                raise RuntimeError("WAL failed to append settlement intent")

            if intent.attempt_id:
                self._committed_attempt_ids.add(intent.attempt_id)
            if intent.outcome == "COMPLETED" and intent.execution_id:
                self._committed_execution_ids.add(intent.execution_id)
            elif intent.execution_id and not intent.attempt_id:
                self._committed_execution_ids.add(intent.execution_id)

            self._append_count += 1
            if (
                self.auto_compact_interval > 0
                and self._append_count % self.auto_compact_interval == 0
            ):
                if self.wal is not None and hasattr(self.wal, "compact_after_snapshot"):
                    try:
                        self.wal.compact_after_snapshot(self.state)
                    except Exception as exc:
                        logger.debug("StateAuthority: Auto-compaction notice: %s", exc)

            return wal_id

    def commit_stage_output(
        self,
        ctx: Any,
        stage_name: str,
        stage_output: StageOutput,
    ) -> SettlementResult:
        """Authoritatively merge a full StageOutput into pipeline context state."""
        from src.core.contracts.state_schema import GLOBAL_STATE_SCHEMA_REGISTRY

        with self._lock:
            exec_id = getattr(stage_output, "stage_name", stage_name)
            state_delta = _to_mutable(dict(stage_output.state_delta))
            committed_findings = _dict_findings_from_delta(state_delta)
            validation_errors = GLOBAL_STATE_SCHEMA_REGISTRY.validate_delta(state_delta)
            if validation_errors:
                raise ValueError(
                    f"Stage '{stage_name}' produced invalid state_delta: "
                    + "; ".join(validation_errors)
                )

            wal_backend = self.wal or getattr(ctx, "_wal", None)
            wal_id: str | None = None
            if wal_backend:
                wal_id = wal_backend.log_delta(stage_name, state_delta)
                if not wal_id:
                    raise RuntimeError(
                        f"WAL durability layer failed for stage '{stage_name}': no durable backend accepted record."
                    )
                if hasattr(ctx.result, "_neural_state"):
                    state_delta = dict(state_delta)
                    state_delta["_wal_id"] = wal_id
                    ctx.result._neural_state.last_wal_id = wal_id

            self.project_stage_output(ctx, stage_name, stage_output, wal_id=wal_id)
            self._committed_execution_ids.add(exec_id)

            return SettlementResult(
                execution_id=exec_id,
                status="COMMITTED",
                wal_id=wal_id,
                committed_findings_count=len(committed_findings),
                committed_findings=committed_findings,
            )

    def project_stage_output(
        self,
        ctx: Any,
        stage_name: str,
        stage_output: StageOutput,
        *,
        wal_id: str | None = None,
    ) -> None:
        """Level-3 ctx projection. Must run only after a durable WAL append."""
        from src.core.models.stage_result import StageStatus
        from src.core.models.stage_status import resolve_skip_status

        state_delta = _to_mutable(dict(stage_output.state_delta))
        if wal_id and hasattr(ctx.result, "_neural_state"):
            state_delta = dict(state_delta)
            state_delta["_wal_id"] = wal_id
            ctx.result._neural_state.last_wal_id = wal_id

        ctx.result.apply_state_delta(state_delta)

        if hasattr(ctx.result.stage_status, "copy"):
            ctx.result.stage_status = dict(ctx.result.stage_status)
        if stage_output.outcome.value == "failed":
            ctx.result.stage_status[stage_name] = StageStatus.FAILED.value
        elif stage_output.outcome.value == "skipped":
            skip_status = resolve_skip_status(stage_output.error or stage_output.reason)
            ctx.result.stage_status[stage_name] = skip_status.value
        else:
            ctx.result.stage_status[stage_name] = StageStatus.COMPLETED.value

        existing_metrics = ctx.result.module_metrics.get(stage_name) or {}
        stage_metrics = _to_mutable(dict(stage_output.metrics))
        merged_metrics: dict[str, Any] = {}
        if isinstance(existing_metrics, dict):
            merged_metrics.update(_to_mutable(existing_metrics))
        merged_metrics.update(stage_metrics)

        merged_metrics.setdefault("status", stage_output.outcome.value)
        merged_metrics.setdefault("duration_seconds", round(stage_output.duration_seconds, 2))
        if stage_output.reason:
            merged_metrics.setdefault("reason", stage_output.reason)
        if stage_output.error:
            merged_metrics.setdefault("error", stage_output.error)
        if hasattr(ctx.result.module_metrics, "copy"):
            ctx.result.module_metrics = dict(ctx.result.module_metrics)
        ctx.result.module_metrics[stage_name] = merged_metrics

        if stage_name == "parameters" and hasattr(ctx.output_store, "write_parameters"):
            ctx.output_store.write_parameters(ctx.result.parameters)
        elif stage_name == "ranking" and hasattr(ctx.output_store, "write_priority_endpoints"):
            ctx.output_store.write_priority_endpoints(ctx.result.priority_urls)


@dataclass(frozen=True, slots=True)
class SettlementIntent:
    """Immutable, durable settlement decision envelope written atomically to the WAL."""

    settlement_id: str
    execution_id: str
    command_id: str = ""
    attempt_id: str = ""
    attempt_n: int = 1
    job_id: str = ""
    candidate_id: str = ""
    lease_id: str = ""
    epoch: int = 1
    partition_id: str = "P0"
    policy_version: str = ""
    outcome: str = "COMPLETED"  # "COMPLETED", "FAILED", "TIMED_OUT", "REJECTED"
    stage_name: str = "execution"
    state_delta: Mapping[str, Any] = field(default_factory=dict)
    budget_action: str = "COMMIT"  # "COMMIT", "RELEASE", "NONE"
    budget_request_count: int = 1
    lease_action: str = "ACK"  # "ACK", "RELEASE", "NONE"
    lease_target_url: str = ""
    lease_worker_id: str = ""
    trace_id: str = ""
    span_id: str = ""
    schema_version: int = 1
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "settlement_id": self.settlement_id,
            "execution_id": self.execution_id,
            "command_id": self.command_id,
            "attempt_id": self.attempt_id,
            "attempt_n": self.attempt_n,
            "job_id": self.job_id,
            "candidate_id": self.candidate_id,
            "lease_id": self.lease_id,
            "epoch": self.epoch,
            "partition_id": self.partition_id,
            "policy_version": self.policy_version,
            "outcome": self.outcome,
            "stage_name": self.stage_name,
            "state_delta": _to_mutable(self.state_delta),
            "budget_action": self.budget_action,
            "budget_request_count": self.budget_request_count,
            "lease_action": self.lease_action,
            "lease_target_url": self.lease_target_url,
            "lease_worker_id": self.lease_worker_id,
            "trace_id": self.trace_id,
            "span_id": self.span_id,
            "schema_version": self.schema_version,
            "created_at": self.created_at,
            "_is_settlement_intent": True,
        }

    @classmethod
    def from_mapping(cls, mapping: Mapping[str, Any]) -> SettlementIntent:
        return cls(
            settlement_id=str(mapping.get("settlement_id") or ""),
            execution_id=str(mapping.get("execution_id") or ""),
            command_id=str(mapping.get("command_id") or ""),
            attempt_id=str(mapping.get("attempt_id") or ""),
            attempt_n=max(1, int(mapping.get("attempt_n") or 1)),
            job_id=str(mapping.get("job_id") or ""),
            candidate_id=str(mapping.get("candidate_id") or ""),
            lease_id=str(mapping.get("lease_id") or ""),
            epoch=int(mapping.get("epoch") or 1),
            partition_id=str(mapping.get("partition_id") or "P0"),
            policy_version=str(mapping.get("policy_version") or ""),
            outcome=str(mapping.get("outcome") or "COMPLETED"),
            stage_name=str(mapping.get("stage_name") or "execution"),
            state_delta=dict(mapping.get("state_delta") or {}),
            budget_action=str(mapping.get("budget_action") or "COMMIT"),
            budget_request_count=int(mapping.get("budget_request_count") or 1),
            lease_action=str(mapping.get("lease_action") or "ACK"),
            lease_target_url=str(mapping.get("lease_target_url") or ""),
            lease_worker_id=str(mapping.get("lease_worker_id") or ""),
            trace_id=str(mapping.get("trace_id") or ""),
            span_id=str(mapping.get("span_id") or ""),
            schema_version=int(mapping.get("schema_version") or 1),
            created_at=float(mapping.get("created_at") or time.time()),
        )


def _intent_already_applied(applied: set[str], intent: SettlementIntent) -> bool:
    """True if this attempt (or a completed execution) has already been projected."""
    if intent.attempt_id and intent.attempt_id in applied:
        return True
    if intent.execution_id and intent.execution_id in applied:
        return True
    return not (intent.attempt_id or intent.execution_id)


def _mark_intent_applied(applied: set[str], intent: SettlementIntent) -> None:
    if intent.attempt_id:
        applied.add(intent.attempt_id)
    if intent.execution_id and (intent.outcome == "COMPLETED" or not intent.attempt_id):
        applied.add(intent.execution_id)


class StateProjection:
    """Projection applying authoritative WAL settlement state deltas into NeuralState CRDT."""

    def __init__(self, state: NeuralState) -> None:
        self.state = state
        self.applied_wal_id: str | None = None
        self.applied_execution_ids: set[str] = set()
        self._lock = threading.RLock()

    def apply(self, intent: SettlementIntent, wal_id: str | None = None) -> bool:
        with self._lock:
            if _intent_already_applied(self.applied_execution_ids, intent):
                if wal_id:
                    self.applied_wal_id = wal_id
                return False

            if intent.outcome == "COMPLETED" and intent.state_delta:
                delta = dict(intent.state_delta)
                if wal_id:
                    delta["_wal_id"] = wal_id
                self.state.apply_delta(delta)

            _mark_intent_applied(self.applied_execution_ids, intent)
            if wal_id:
                self.applied_wal_id = wal_id
            return True


class BudgetProjection:
    """Projection applying authoritative budget commits/releases to HuntBudgetEnforcer."""

    def __init__(self, budget_enforcer: Any | None = None) -> None:
        self.budget_enforcer = budget_enforcer
        self.applied_wal_id: str | None = None
        self.applied_execution_ids: set[str] = set()
        self._lock = threading.RLock()

    def apply(self, intent: SettlementIntent, wal_id: str | None = None) -> bool:
        with self._lock:
            if _intent_already_applied(self.applied_execution_ids, intent):
                if wal_id:
                    self.applied_wal_id = wal_id
                return False

            if self.budget_enforcer is not None:
                if intent.budget_action == "COMMIT" and hasattr(
                    self.budget_enforcer, "commit_requests"
                ):
                    self.budget_enforcer.commit_requests(intent.budget_request_count)
                elif intent.budget_action == "RELEASE" and hasattr(
                    self.budget_enforcer, "release_requests"
                ):
                    self.budget_enforcer.release_requests(intent.budget_request_count)

            _mark_intent_applied(self.applied_execution_ids, intent)
            if wal_id:
                self.applied_wal_id = wal_id
            return True


class LeaseProjection:
    """Projection applying authoritative queue lease acknowledgements/releases with stale protection."""

    def __init__(self, queue: Any | None = None) -> None:
        self.queue = queue
        self.applied_wal_id: str | None = None
        self.applied_execution_ids: set[str] = set()
        self._lock = threading.RLock()

    def apply(self, intent: SettlementIntent, wal_id: str | None = None) -> bool:
        with self._lock:
            if _intent_already_applied(self.applied_execution_ids, intent):
                if wal_id:
                    self.applied_wal_id = wal_id
                return False

            if self.queue is not None:
                lease_obj = None
                if intent.lease_id and intent.lease_target_url:
                    lease_obj = CandidateLease(
                        candidate_id=intent.candidate_id or "cand_proj",
                        target_url=intent.lease_target_url,
                        execution_id=intent.execution_id,
                        lease_id=intent.lease_id,
                        worker_id=intent.lease_worker_id,
                        expires_at=intent.created_at + 60.0,
                        epoch=intent.epoch,
                        partition_id=intent.partition_id,
                    )
                if lease_obj is not None:
                    if intent.lease_action == "ACK" and hasattr(self.queue, "ack_batch"):
                        self.queue.ack_batch([lease_obj])
                    elif intent.lease_action == "RELEASE" and hasattr(self.queue, "release_batch"):
                        self.queue.release_batch([lease_obj])

            _mark_intent_applied(self.applied_execution_ids, intent)
            if wal_id:
                self.applied_wal_id = wal_id
            return True


class FindingsProjection:
    """Projection accumulating deduplicated findings from settled execution intents."""

    def __init__(self) -> None:
        self._findings: dict[str, Finding] = {}
        self.applied_wal_id: str | None = None
        self.applied_execution_ids: set[str] = set()
        self._lock = threading.RLock()

    @property
    def findings(self) -> list[Finding]:
        with self._lock:
            return list(self._findings.values())

    def apply(self, intent: SettlementIntent, wal_id: str | None = None) -> bool:
        with self._lock:
            if _intent_already_applied(self.applied_execution_ids, intent):
                if wal_id:
                    self.applied_wal_id = wal_id
                return False

            if intent.outcome == "COMPLETED" and intent.state_delta:
                raw_findings = intent.state_delta.get("findings") or []
                for f_data in raw_findings:
                    if isinstance(f_data, Finding):
                        finding = f_data
                    elif isinstance(f_data, Mapping):
                        finding = Finding.from_mapping(f_data)
                    else:
                        continue
                    key = (
                        finding.key()
                        if hasattr(finding, "key")
                        else f"{getattr(finding, 'category', 'c')}:{getattr(finding, 'url', 'u')}"
                    )
                    self._findings[key] = finding

            _mark_intent_applied(self.applied_execution_ids, intent)
            if wal_id:
                self.applied_wal_id = wal_id
            return True


class SettlementProjectionEngine:
    """Orchestrates independent projections and catches up from the WAL upon restart or projection lag."""

    def __init__(
        self,
        state_projection: StateProjection,
        budget_projection: BudgetProjection,
        lease_projection: LeaseProjection,
        findings_projection: FindingsProjection | None = None,
    ) -> None:
        self.state_projection = state_projection
        self.budget_projection = budget_projection
        self.lease_projection = lease_projection
        self.findings_projection = findings_projection or FindingsProjection()
        self._lock = threading.RLock()

    def apply_intent(self, intent: SettlementIntent, wal_id: str | None = None) -> None:
        """Forward an intent to all projections (advancing each projection independently)."""
        with self._lock:
            try:
                self.state_projection.apply(intent, wal_id)
            except Exception as exc:
                logger.error(
                    "ProjectionEngine: State projection error for %s: %s", intent.execution_id, exc
                )

            try:
                self.budget_projection.apply(intent, wal_id)
            except Exception as exc:
                logger.error(
                    "ProjectionEngine: Budget projection error for %s: %s", intent.execution_id, exc
                )

            try:
                self.lease_projection.apply(intent, wal_id)
            except Exception as exc:
                logger.error(
                    "ProjectionEngine: Lease projection error for %s: %s", intent.execution_id, exc
                )

            try:
                self.findings_projection.apply(intent, wal_id)
            except Exception as exc:
                logger.error(
                    "ProjectionEngine: Findings projection error for %s: %s",
                    intent.execution_id,
                    exc,
                )

    def replay_from_wal(self, wal: Any) -> dict[str, int]:
        """Catch up any lagging projections from the WAL log entries."""
        with self._lock:
            if hasattr(wal, "since"):
                entries = wal.since(None)
            elif hasattr(wal, "recover_deltas"):
                entries = wal.recover_deltas()
            elif hasattr(wal, "_entries"):
                entries = list(wal._entries)
            else:
                entries = []

            applied_counts = {"state": 0, "budget": 0, "lease": 0, "findings": 0}
            for entry in entries:
                wal_id = str(entry.get("_wal_id") or "")
                if entry.get("_is_settlement_intent"):
                    intent = SettlementIntent.from_mapping(entry)
                elif "execution_id" in entry and (
                    "state_delta" in entry or "budget_action" in entry
                ):
                    intent = SettlementIntent.from_mapping(entry)
                else:
                    intent = SettlementIntent(
                        settlement_id=f"stl_rec_{wal_id}",
                        execution_id=str(entry.get("execution_id") or f"exec_rec_{wal_id}"),
                        outcome="COMPLETED",
                        state_delta=dict(entry),
                        budget_action="NONE",
                        lease_action="NONE",
                    )

                if self.state_projection.apply(intent, wal_id):
                    applied_counts["state"] += 1
                if self.budget_projection.apply(intent, wal_id):
                    applied_counts["budget"] += 1
                if self.lease_projection.apply(intent, wal_id):
                    applied_counts["lease"] += 1
                if self.findings_projection.apply(intent, wal_id):
                    applied_counts["findings"] += 1

            return applied_counts


class SettlementCoordinator:
    """Coordinates validation, construction of immutable SettlementIntent, and durable projection dispatch."""

    def __init__(
        self,
        state_authority: StateAuthority,
        budget_enforcer: Any | None = None,
        queue: Any | None = None,
        partition_router: Any | None = None,
    ) -> None:
        self.state_authority = state_authority
        self.budget_enforcer = budget_enforcer
        self.queue = queue
        self.partition_router = partition_router

        self.state_projection = StateProjection(self.state_authority.state)
        self.budget_projection = BudgetProjection(self.budget_enforcer)
        self.lease_projection = LeaseProjection(self.queue)
        self.findings_projection = FindingsProjection()
        self.projection_engine = SettlementProjectionEngine(
            self.state_projection,
            self.budget_projection,
            self.lease_projection,
            self.findings_projection,
        )
        self._lock = threading.RLock()

    def settle_claim(
        self,
        claim: RawExecutionClaim,
        ticket: Any | None = None,
        request_count: int = 1,
    ) -> SettlementResult:
        """5-Stage verification and atomic settlement of an untrusted RawExecutionClaim."""
        with self._lock:
            exec_id = claim.execution_id or ""

            # 0. Enforce 64 KB bound
            if hasattr(claim, "validate_bounds"):
                try:
                    claim.validate_bounds()
                except Exception as exc:
                    return SettlementResult(
                        execution_id=exec_id,
                        status="REJECTED",
                        error=f"Claim bound validation failed: {exc}",
                    )

            # 1. Deduplication check
            if exec_id and self.state_authority.is_committed(exec_id):
                return SettlementResult(
                    execution_id=exec_id,
                    status="DEDUPLICATED",
                    committed_findings_count=len(claim.findings),
                    committed_deltas_count=len(claim.state_deltas),
                )

            # 2. Ticket / Epoch / Nonce / Policy verification if ticket supplied
            if ticket is not None:
                if hasattr(ticket, "epoch") and claim.ticket_epoch != ticket.epoch:
                    return SettlementResult(
                        execution_id=exec_id,
                        status="REJECTED",
                        error=f"Epoch mismatch: claim.ticket_epoch ({claim.ticket_epoch}) != ticket.epoch ({ticket.epoch})",
                    )
                if hasattr(ticket, "nonce") and claim.ticket_nonce:
                    if ticket.nonce != claim.ticket_nonce:
                        return SettlementResult(
                            execution_id=exec_id,
                            status="REJECTED",
                            error="Ticket nonce mismatch: Potential replay attack detected",
                        )
                if (
                    hasattr(ticket, "policy_generation")
                    and claim.policy_generation != ticket.policy_generation
                ):
                    return SettlementResult(
                        execution_id=exec_id,
                        status="REJECTED",
                        error=f"Policy generation mismatch: claim ({claim.policy_generation}) != ticket ({ticket.policy_generation})",
                    )

            # 3. CAS Merkle Root & Evidence Integrity Verification (Invariant I27)
            if claim.cas_merkle_root and claim.evidence_hashes:
                from src.core.storage.cas_store import get_global_cas_store

                cas_store = get_global_cas_store()
                if not cas_store.verify_merkle_root(claim.evidence_hashes, claim.cas_merkle_root):
                    return SettlementResult(
                        execution_id=exec_id,
                        status="REJECTED",
                        error="CAS evidence integrity verification failed (I27): Merkle root mismatch or missing blob",
                    )

            # 4. Partition Fencing / Epoch check if partition router supplied
            if self.partition_router is not None and claim.candidate_id:
                partition = self.partition_router.route_and_get_partition(claim.candidate_id)
                fencing_ok, reason = partition.validate_claim_fencing(claim)
                if not fencing_ok:
                    logger.warning("Fencing rejection for execution %s: %s", exec_id, reason)
                    return SettlementResult(
                        execution_id=exec_id,
                        status="REJECTED",
                        error=f"Fencing validation failed: {reason}",
                    )
                # If claim is accepted, settle the lease in partition
                partition.settle_lease(claim.candidate_id, claim.lease_id)

            # 4. Construct ExecutionResult and forward to settle
            exec_result = ExecutionResult(
                request_id=claim.request_id,
                tenant_id=claim.tenant_id,
                outcome=claim.outcome,
                duration_seconds=claim.duration_seconds,
                findings=claim.findings,
                state_deltas=claim.state_deltas,
                resource_consumption=claim.resource_consumption,
                error=claim.error,
                execution_id=claim.execution_id,
                candidate_id=claim.candidate_id,
                lease_id=claim.lease_id,
                policy_version=claim.policy_version,
            )

            lease = CandidateLease(
                candidate_id=claim.candidate_id,
                target_url="",
                execution_id=claim.execution_id,
                lease_id=claim.lease_id,
                worker_id=claim.worker_id,
                expires_at=time.time() + 60.0,
                epoch=claim.epoch,
            )

            return self.settle(
                result=exec_result,
                lease=lease,
                request_count=request_count,
            )

    def settle(
        self,
        result: ExecutionResult,
        lease: CandidateLease | None = None,
        stage_name: str = "execution",
        request_count: int = 1,
    ) -> SettlementResult:
        """Validates intent and appends to the WAL, followed by projection updates."""
        with self._lock:
            exec_id = result.execution_id or ""
            identity = (
                mint_causal_identity(
                    execution_id=exec_id,
                    command_id=str(getattr(result, "command_id", "") or ""),
                    attempt_n=max(1, int(getattr(result, "attempt_n", 1) or 1)),
                )
                if exec_id
                else None
            )
            if identity is not None:
                if self.state_authority.is_attempt_committed(identity.attempt_id):
                    return SettlementResult(
                        execution_id=exec_id,
                        status="DEDUPLICATED",
                        committed_findings_count=len(result.findings),
                        committed_deltas_count=len(result.state_deltas),
                        command_id=identity.command_id,
                        attempt_id=identity.attempt_id,
                        settlement_id=identity.settlement_id,
                    )
            if exec_id and self.state_authority.is_committed(exec_id):
                return SettlementResult(
                    execution_id=exec_id,
                    status="DEDUPLICATED",
                    committed_findings_count=len(result.findings),
                    committed_deltas_count=len(result.state_deltas),
                    command_id=identity.command_id if identity else "",
                    attempt_id=identity.attempt_id if identity else "",
                    settlement_id=identity.settlement_id if identity else "",
                )

            # Convert result findings & deltas
            deltas_dict: dict[str, Any] = dict(result.state_deltas)
            if result.findings:
                deltas_dict["findings"] = [f.to_dict() for f in result.findings]

            # Determine actions
            if result.outcome == "COMPLETED":
                budget_action = "COMMIT"
                lease_action = "ACK"
            else:
                budget_action = "RELEASE"
                lease_action = "RELEASE"

            intent = SettlementIntent(
                settlement_id=(
                    identity.settlement_id if identity else f"stl_{uuid.uuid4().hex[:12]}"
                ),
                execution_id=exec_id,
                command_id=identity.command_id if identity else "",
                attempt_id=identity.attempt_id if identity else "",
                attempt_n=identity.attempt_n if identity else 1,
                job_id=result.job_id or "",
                candidate_id=result.candidate_id or (lease.candidate_id if lease else ""),
                lease_id=result.lease_id or (lease.lease_id if lease else ""),
                epoch=lease.epoch if lease else 1,
                partition_id=lease.partition_id if lease else "P0",
                policy_version=result.policy_version or "",
                outcome=result.outcome,
                stage_name=stage_name,
                state_delta=deltas_dict,
                budget_action=budget_action,
                budget_request_count=request_count,
                lease_action=lease_action,
                lease_target_url=lease.target_url if lease else "",
                lease_worker_id=lease.worker_id if lease else "",
            )

            # 1. Authoritative WAL append (Single Point of Truth)
            try:
                wal_id = self.state_authority.append_settlement_intent(intent)
            except Exception as exc:
                logger.exception(
                    "SettlementCoordinator: WAL append failed for execution %s", exec_id
                )
                return SettlementResult(
                    execution_id=exec_id,
                    status="REJECTED",
                    error=f"WAL settlement append failure: {exc}",
                    command_id=intent.command_id,
                    attempt_id=intent.attempt_id,
                    settlement_id=intent.settlement_id,
                )

            if wal_id == "DEDUPLICATED":
                return SettlementResult(
                    execution_id=exec_id,
                    status="DEDUPLICATED",
                    command_id=intent.command_id,
                    attempt_id=intent.attempt_id,
                    settlement_id=intent.settlement_id,
                )

            # 2. Drive projections
            self.projection_engine.apply_intent(intent, wal_id=wal_id)

            status = "COMMITTED" if result.outcome == "COMPLETED" else "REJECTED"
            committed_findings = _dict_findings_from_delta(deltas_dict)
            return SettlementResult(
                execution_id=exec_id,
                status=status,
                wal_id=wal_id,
                committed_findings_count=len(committed_findings) or len(result.findings),
                committed_deltas_count=len(result.state_deltas),
                error=result.error if status == "REJECTED" else "",
                committed_findings=committed_findings,
                command_id=intent.command_id,
                attempt_id=intent.attempt_id,
                settlement_id=intent.settlement_id,
            )

    def replay_projections(self, wal: Any | None = None) -> dict[str, int]:
        """Catch up all projections from the durable WAL."""
        target_wal = wal or self.state_authority.wal
        if target_wal is None:
            return {"state": 0, "budget": 0, "lease": 0, "findings": 0}
        return self.projection_engine.replay_from_wal(target_wal)

    def settle_stage_output(
        self,
        ctx: Any,
        stage_name: str,
        stage_output: StageOutput,
    ) -> SettlementResult:
        """Settle a stage through SettlementIntent (WAL) then project onto ctx."""
        run_id = str(getattr(ctx, "run_id", "") or "")
        exec_id = f"{run_id}:{stage_name}" if run_id else str(stage_name)
        identity = mint_causal_identity(
            execution_id=exec_id,
            command_id=command_id_from_ctx(ctx, exec_id),
            attempt_n=attempt_n_from_output(stage_output),
        )
        if self.state_authority.is_attempt_committed(identity.attempt_id):
            return SettlementResult(
                execution_id=exec_id,
                status="DEDUPLICATED",
                command_id=identity.command_id,
                attempt_id=identity.attempt_id,
                settlement_id=identity.settlement_id,
            )
        if exec_id and self.state_authority.is_committed(exec_id):
            return SettlementResult(
                execution_id=exec_id,
                status="DEDUPLICATED",
                command_id=identity.command_id,
                attempt_id=identity.attempt_id,
                settlement_id=identity.settlement_id,
            )

        from src.core.frontier.region_model import (
            DEFAULT_REGION_ID,
            assert_lease_settle_colocated,
        )

        acquire = str(getattr(ctx, "home_region", "") or DEFAULT_REGION_ID)
        settle_region = str(getattr(ctx, "settle_region", "") or acquire)
        assert_lease_settle_colocated(acquire_region=acquire, settle_region=settle_region)

        state_delta = _to_mutable(getattr(stage_output, "state_delta", {}) or {})
        committed_findings = _dict_findings_from_delta(state_delta)
        outcome_value = str(getattr(getattr(stage_output, "outcome", None), "value", "") or "")
        if outcome_value == "failed":
            outcome = "FAILED"
        elif outcome_value == "skipped":
            outcome = "SKIPPED"
        else:
            outcome = "COMPLETED"
        intent = SettlementIntent(
            settlement_id=identity.settlement_id,
            execution_id=exec_id,
            command_id=identity.command_id,
            attempt_id=identity.attempt_id,
            attempt_n=identity.attempt_n,
            stage_name=stage_name,
            outcome=outcome,
            state_delta=state_delta,
            budget_action="NONE",
            lease_action="NONE",
        )
        try:
            wal_id = self.state_authority.append_settlement_intent(intent)
        except Exception as exc:
            logger.exception("settle_stage_output: WAL append failed for %s", exec_id)
            return SettlementResult(
                execution_id=exec_id,
                status="REJECTED",
                error=f"WAL settlement append failure: {exc}",
                command_id=identity.command_id,
                attempt_id=identity.attempt_id,
                settlement_id=identity.settlement_id,
            )
        if wal_id == "DEDUPLICATED":
            return SettlementResult(
                execution_id=exec_id,
                status="DEDUPLICATED",
                command_id=identity.command_id,
                attempt_id=identity.attempt_id,
                settlement_id=identity.settlement_id,
            )

        self.state_authority.project_stage_output(ctx, stage_name, stage_output, wal_id=wal_id)
        self.projection_engine.apply_intent(intent, wal_id=wal_id)
        return SettlementResult(
            execution_id=exec_id,
            status="COMMITTED" if outcome == "COMPLETED" else "REJECTED",
            wal_id=wal_id,
            committed_findings_count=len(committed_findings),
            committed_findings=committed_findings,
            error=""
            if outcome == "COMPLETED"
            else (stage_output.error or stage_output.reason or ""),
            command_id=identity.command_id,
            attempt_id=identity.attempt_id,
            settlement_id=identity.settlement_id,
        )


__all__ = [
    "BudgetProjection",
    "FindingsProjection",
    "LeaseProjection",
    "SettlementCoordinator",
    "SettlementIntent",
    "SettlementProjectionEngine",
    "SettlementResult",
    "StateAuthority",
    "StateProjection",
]
