"""Authoritative state and settlement engine for the Cyber Security Test Pipeline.

Implements the single-commit StateAuthority (WAL -> CRDT -> Execution ID Commit)
and the SettlementCoordinator coordinating atomic budget and state settlement.
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from src.core.contracts.pipeline_runtime import StageOutput
from src.core.frontier.state import NeuralState
from src.decision.models import CandidateLease, ExecutionResult

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class SettlementResult:
    """Outcome of settling an ExecutionResult or StageOutput."""

    execution_id: str
    status: str  # "COMMITTED", "DEDUPLICATED", "REJECTED"
    wal_id: str | None = None
    committed_findings_count: int = 0
    committed_deltas_count: int = 0
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "execution_id": self.execution_id,
            "status": self.status,
            "wal_id": self.wal_id,
            "committed_findings_count": self.committed_findings_count,
            "committed_deltas_count": self.committed_deltas_count,
            "error": self.error,
        }


class StateAuthority:
    """Single-source-of-truth State Merge & Durability Authority."""

    def __init__(
        self,
        state: NeuralState | None = None,
        wal: Any | None = None,
        cache: Any | None = None,
    ) -> None:
        self.state = state if state is not None else NeuralState()
        self.wal = wal
        self.cache = cache
        self._committed_execution_ids: set[str] = set()
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
            if intent.execution_id and intent.execution_id in self._committed_execution_ids:
                return "DEDUPLICATED"

            envelope = intent.to_dict()
            wal_id: str | None = None
            if self.wal is not None:
                if hasattr(self.wal, "log_delta"):
                    wal_id = self.wal.log_delta(intent.stage_name, envelope)
                elif hasattr(self.wal, "append"):
                    wal_id = self.wal.append(envelope)
            else:
                import uuid
                wal_id = f"wal_{uuid.uuid4().hex[:8]}"

            if not wal_id:
                raise RuntimeError("WAL failed to append settlement intent")

            if intent.execution_id:
                self._committed_execution_ids.add(intent.execution_id)

            return wal_id

    def commit_stage_output(
        self,
        ctx: Any,
        stage_name: str,
        stage_output: StageOutput,
    ) -> SettlementResult:
        """Authoritatively merge a full StageOutput into pipeline context state."""
        from src.core.contracts.state_schema import GLOBAL_STATE_SCHEMA_REGISTRY
        from src.core.models.stage_result import StageStatus
        from src.core.models.stage_status import resolve_skip_status
        from src.pipeline.services.pipeline_orchestrator._orchestrator.utils import (
            StageOutputValidationError,
            _validate_stage_output_contract,
        )

        def _to_mutable(value: Any) -> Any:
            if isinstance(value, Mapping):
                return {k: _to_mutable(v) for k, v in value.items()}
            if isinstance(value, (tuple, list, set, frozenset)):
                return [_to_mutable(item) for item in value]
            return value

        with self._lock:
            exec_id = getattr(stage_output, "stage_name", stage_name)
            _validate_stage_output_contract(stage_name, stage_output)
            state_delta = _to_mutable(dict(stage_output.state_delta))
            validation_errors = GLOBAL_STATE_SCHEMA_REGISTRY.validate_delta(state_delta)
            if validation_errors:
                raise StageOutputValidationError(
                    f"Stage '{stage_name}' produced invalid state_delta: " + "; ".join(validation_errors)
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
            merged_metrics = {}
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

            self._committed_execution_ids.add(exec_id)

            return SettlementResult(
                execution_id=exec_id,
                status="COMMITTED",
                wal_id=wal_id,
            )


@dataclass(frozen=True, slots=True)
class SettlementIntent:
    """Immutable, durable settlement decision envelope written atomically to the WAL."""

    settlement_id: str
    execution_id: str
    job_id: str = ""
    candidate_id: str = ""
    lease_id: str = ""
    policy_version: str = ""
    outcome: str = "COMPLETED"  # "COMPLETED", "FAILED", "TIMED_OUT", "REJECTED"
    stage_name: str = "execution"
    state_delta: Mapping[str, Any] = field(default_factory=dict)
    budget_action: str = "COMMIT"  # "COMMIT", "RELEASE", "NONE"
    budget_request_count: int = 1
    lease_action: str = "ACK"  # "ACK", "RELEASE", "NONE"
    lease_target_url: str = ""
    lease_worker_id: str = ""
    schema_version: int = 1
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "settlement_id": self.settlement_id,
            "execution_id": self.execution_id,
            "job_id": self.job_id,
            "candidate_id": self.candidate_id,
            "lease_id": self.lease_id,
            "policy_version": self.policy_version,
            "outcome": self.outcome,
            "stage_name": self.stage_name,
            "state_delta": dict(self.state_delta),
            "budget_action": self.budget_action,
            "budget_request_count": self.budget_request_count,
            "lease_action": self.lease_action,
            "lease_target_url": self.lease_target_url,
            "lease_worker_id": self.lease_worker_id,
            "schema_version": self.schema_version,
            "created_at": self.created_at,
            "_is_settlement_intent": True,
        }

    @classmethod
    def from_mapping(cls, mapping: Mapping[str, Any]) -> SettlementIntent:
        return cls(
            settlement_id=str(mapping.get("settlement_id") or ""),
            execution_id=str(mapping.get("execution_id") or ""),
            job_id=str(mapping.get("job_id") or ""),
            candidate_id=str(mapping.get("candidate_id") or ""),
            lease_id=str(mapping.get("lease_id") or ""),
            policy_version=str(mapping.get("policy_version") or ""),
            outcome=str(mapping.get("outcome") or "COMPLETED"),
            stage_name=str(mapping.get("stage_name") or "execution"),
            state_delta=dict(mapping.get("state_delta") or {}),
            budget_action=str(mapping.get("budget_action") or "COMMIT"),
            budget_request_count=int(mapping.get("budget_request_count") or 1),
            lease_action=str(mapping.get("lease_action") or "ACK"),
            lease_target_url=str(mapping.get("lease_target_url") or ""),
            lease_worker_id=str(mapping.get("lease_worker_id") or ""),
            schema_version=int(mapping.get("schema_version") or 1),
            created_at=float(mapping.get("created_at") or time.time()),
        )


class StateProjection:
    """Projection applying authoritative WAL settlement state deltas into NeuralState CRDT."""

    def __init__(self, state: NeuralState) -> None:
        self.state = state
        self.applied_wal_id: str | None = None
        self.applied_execution_ids: set[str] = set()
        self._lock = threading.RLock()

    def apply(self, intent: SettlementIntent, wal_id: str | None = None) -> bool:
        with self._lock:
            if not intent.execution_id or intent.execution_id in self.applied_execution_ids:
                if wal_id:
                    self.applied_wal_id = wal_id
                return False

            if intent.outcome == "COMPLETED" and intent.state_delta:
                delta = dict(intent.state_delta)
                if wal_id:
                    delta["_wal_id"] = wal_id
                self.state.apply_delta(delta)

            if intent.execution_id:
                self.applied_execution_ids.add(intent.execution_id)
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
            if not intent.execution_id or intent.execution_id in self.applied_execution_ids:
                if wal_id:
                    self.applied_wal_id = wal_id
                return False

            if self.budget_enforcer is not None:
                if intent.budget_action == "COMMIT" and hasattr(self.budget_enforcer, "commit_requests"):
                    self.budget_enforcer.commit_requests(intent.budget_request_count)
                elif intent.budget_action == "RELEASE" and hasattr(self.budget_enforcer, "release_requests"):
                    self.budget_enforcer.release_requests(intent.budget_request_count)

            if intent.execution_id:
                self.applied_execution_ids.add(intent.execution_id)
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
            if not intent.execution_id or intent.execution_id in self.applied_execution_ids:
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
                    )
                if lease_obj is not None:
                    if intent.lease_action == "ACK" and hasattr(self.queue, "ack_batch"):
                        self.queue.ack_batch([lease_obj])
                    elif intent.lease_action == "RELEASE" and hasattr(self.queue, "release_batch"):
                        self.queue.release_batch([lease_obj])

            if intent.execution_id:
                self.applied_execution_ids.add(intent.execution_id)
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
    ) -> None:
        self.state_projection = state_projection
        self.budget_projection = budget_projection
        self.lease_projection = lease_projection
        self._lock = threading.RLock()

    def apply_intent(self, intent: SettlementIntent, wal_id: str | None = None) -> None:
        """Forward an intent to all projections (advancing each projection independently)."""
        with self._lock:
            try:
                self.state_projection.apply(intent, wal_id)
            except Exception as exc:
                logger.error("ProjectionEngine: State projection error for %s: %s", intent.execution_id, exc)

            try:
                self.budget_projection.apply(intent, wal_id)
            except Exception as exc:
                logger.error("ProjectionEngine: Budget projection error for %s: %s", intent.execution_id, exc)

            try:
                self.lease_projection.apply(intent, wal_id)
            except Exception as exc:
                logger.error("ProjectionEngine: Lease projection error for %s: %s", intent.execution_id, exc)

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

            applied_counts = {"state": 0, "budget": 0, "lease": 0}
            for entry in entries:
                wal_id = str(entry.get("_wal_id") or "")
                if entry.get("_is_settlement_intent"):
                    intent = SettlementIntent.from_mapping(entry)
                elif "execution_id" in entry and ("state_delta" in entry or "budget_action" in entry):
                    intent = SettlementIntent.from_mapping(entry)
                else:
                    # Generic delta envelope compatibility
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

            return applied_counts


class SettlementCoordinator:
    """Coordinates validation, construction of immutable SettlementIntent, and durable projection dispatch."""

    def __init__(
        self,
        state_authority: StateAuthority,
        budget_enforcer: Any | None = None,
        queue: Any | None = None,
    ) -> None:
        self.state_authority = state_authority
        self.budget_enforcer = budget_enforcer
        self.queue = queue

        self.state_projection = StateProjection(self.state_authority.state)
        self.budget_projection = BudgetProjection(self.budget_enforcer)
        self.lease_projection = LeaseProjection(self.queue)
        self.projection_engine = SettlementProjectionEngine(
            self.state_projection,
            self.budget_projection,
            self.lease_projection,
        )
        self._lock = threading.RLock()

    def settle(
        self,
        result: ExecutionResult,
        lease: CandidateLease | None = None,
        stage_name: str = "execution",
        request_count: int = 1,
    ) -> SettlementResult:
        """Validates intent and appends to the WAL, followed by projection updates."""
        import uuid

        with self._lock:
            exec_id = result.execution_id or ""
            if exec_id and self.state_authority.is_committed(exec_id):
                return SettlementResult(
                    execution_id=exec_id,
                    status="DEDUPLICATED",
                    committed_findings_count=len(result.findings),
                    committed_deltas_count=len(result.state_deltas),
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
                settlement_id=f"stl_{uuid.uuid4().hex[:12]}",
                execution_id=exec_id,
                job_id=result.job_id or "",
                candidate_id=result.candidate_id or (lease.candidate_id if lease else ""),
                lease_id=result.lease_id or (lease.lease_id if lease else ""),
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
                logger.exception("SettlementCoordinator: WAL append failed for execution %s", exec_id)
                return SettlementResult(
                    execution_id=exec_id,
                    status="REJECTED",
                    error=f"WAL settlement append failure: {exc}",
                )

            if wal_id == "DEDUPLICATED":
                return SettlementResult(
                    execution_id=exec_id,
                    status="DEDUPLICATED",
                )

            # 2. Drive projections
            self.projection_engine.apply_intent(intent, wal_id=wal_id)

            status = "COMMITTED" if result.outcome == "COMPLETED" else "REJECTED"
            return SettlementResult(
                execution_id=exec_id,
                status=status,
                wal_id=wal_id,
                committed_findings_count=len(result.findings),
                committed_deltas_count=len(result.state_deltas),
                error=result.error if status == "REJECTED" else "",
            )

    def replay_projections(self, wal: Any | None = None) -> dict[str, int]:
        """Catch up all projections from the durable WAL."""
        target_wal = wal or self.state_authority.wal
        if target_wal is None:
            return {"state": 0, "budget": 0, "lease": 0}
        return self.projection_engine.replay_from_wal(target_wal)

    def settle_stage_output(
        self,
        ctx: Any,
        stage_name: str,
        stage_output: StageOutput,
    ) -> SettlementResult:
        """Atomically settle a complete stage output."""
        return self.state_authority.commit_stage_output(ctx, stage_name, stage_output)


__all__ = [
    "BudgetProjection",
    "LeaseProjection",
    "SettlementCoordinator",
    "SettlementIntent",
    "SettlementProjectionEngine",
    "SettlementResult",
    "StateAuthority",
    "StateProjection",
]
