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


class SettlementCoordinator:
    """Coordinates budget settlement, state settlement, and candidate lease lifecycle."""

    def __init__(
        self,
        state_authority: StateAuthority,
        budget_enforcer: Any | None = None,
        queue: Any | None = None,
    ) -> None:
        self.state_authority = state_authority
        self.budget_enforcer = budget_enforcer
        self.queue = queue
        self._lock = threading.Lock()

    def settle(
        self,
        result: ExecutionResult,
        lease: CandidateLease | None = None,
        stage_name: str = "execution",
        request_count: int = 1,
    ) -> SettlementResult:
        """Atomically settle budget, commit state, and acknowledge/release queue leases."""
        with self._lock:
            # Case 1: Completed Execution
            if result.outcome == "COMPLETED":
                settle_res = self.state_authority.commit(result, stage_name=stage_name)
                if settle_res.status in ("COMMITTED", "DEDUPLICATED"):
                    if self.budget_enforcer is not None and hasattr(self.budget_enforcer, "commit_requests"):
                        self.budget_enforcer.commit_requests(request_count)
                    if self.queue is not None and lease is not None and hasattr(self.queue, "ack_batch"):
                        self.queue.ack_batch([lease])
                    return settle_res
                else:
                    # State commit failed: release budget and lease
                    if self.budget_enforcer is not None and hasattr(self.budget_enforcer, "release_requests"):
                        self.budget_enforcer.release_requests(request_count)
                    if self.queue is not None and lease is not None and hasattr(self.queue, "release_batch"):
                        self.queue.release_batch([lease])
                    return settle_res

            # Case 2: Failed, Timed Out, or Rejected Execution
            else:
                if self.budget_enforcer is not None and hasattr(self.budget_enforcer, "release_requests"):
                    self.budget_enforcer.release_requests(request_count)
                if self.queue is not None and lease is not None and hasattr(self.queue, "release_batch"):
                    self.queue.release_batch([lease])

                return SettlementResult(
                    execution_id=result.execution_id,
                    status="REJECTED",
                    error=result.error or f"Execution ended with outcome {result.outcome}",
                )

    def settle_stage_output(
        self,
        ctx: Any,
        stage_name: str,
        stage_output: StageOutput,
    ) -> SettlementResult:
        """Atomically settle a complete stage output."""
        return self.state_authority.commit_stage_output(ctx, stage_name, stage_output)



__all__ = [
    "SettlementCoordinator",
    "SettlementResult",
    "StateAuthority",
]
