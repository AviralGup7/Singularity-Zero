"""Construct the live CLI/dashboard authority bundle outside ``src.core``.

HuntBudget, the Bayesian bandit, and ExecutionAuthorizer live in
``src.decision`` and must not be imported by the core layer (architecture
purity). This module is the only factory the scan path should call.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

from src.core.frontier.authority_runtime import PipelineAuthorityRuntime
from src.decision.authorization import ExecutionAuthorizer
from src.decision.bayesian_bandit import BayesianParameterBandit
from src.decision.hunt_budget import HuntBudget, HuntBudgetEnforcer


def build_pipeline_authority_runtime(
    *,
    run_id: str,
    scan_wal: Any | None = None,
    raft_wal_dir: Path | str | None = None,
    spool_dir: Path | str | None = None,
    outbox_dir: Path | str | None = None,
    total_budget: int = 10_000,
    transport: Any | None = None,
    node_id: str = "",
) -> PipelineAuthorityRuntime:
    """Build a single-node authority runtime with decision adapters injected."""
    runtime = PipelineAuthorityRuntime(
        run_id=run_id,
        scan_wal=scan_wal,
        raft_wal_dir=raft_wal_dir,
        spool_dir=spool_dir,
        outbox_dir=outbox_dir,
        total_budget=total_budget,
        transport=transport,
        node_id=node_id,
    )
    runtime.hunt_budget = HuntBudgetEnforcer(
        HuntBudget(max_requests=int(total_budget), label=run_id),
        global_budget=runtime.global_budget,
        partition_id="P-0000",
        run_id=run_id,
        placement=runtime.placement,
    )
    try:
        from src.resilience.circuit_breaker import CircuitState, ToolCircuitBreaker

        breaker = ToolCircuitBreaker()
        runtime.hunt_budget.set_reserve_gate(
            lambda: breaker.get_state("hunt") is not CircuitState.OPEN
        )
        runtime.circuit_breaker = breaker
    except Exception:
        runtime.hunt_budget.set_reserve_gate(None)
    runtime.bandit = BayesianParameterBandit()
    runtime.authorizer = ExecutionAuthorizer(budget_enforcer=runtime.hunt_budget)
    runtime.settlement.budget_enforcer = runtime.hunt_budget
    return runtime


def resolve_execution_authorizer(
    *,
    ctx: Any | None = None,
    budget_enforcer: Any | None = None,
) -> ExecutionAuthorizer:
    """Prefer the live CLI authorizer so every stage shares one budget."""
    runtime = getattr(ctx, "authority_runtime", None) if ctx is not None else None
    if runtime is not None and getattr(runtime, "authorizer", None) is not None:
        return cast(ExecutionAuthorizer, runtime.authorizer)
    enforcer = budget_enforcer
    if enforcer is None and ctx is not None:
        enforcer = getattr(ctx, "budget_enforcer", None)
    if enforcer is None:
        from src.core.frontier.authority_runtime import get_current_hunt_budget

        enforcer = get_current_hunt_budget()
    return ExecutionAuthorizer(budget_enforcer=enforcer)


def attach_pipeline_authority(
    orchestrator: Any, run_id: str, config: Any
) -> PipelineAuthorityRuntime:
    """Build and bind authority objects after the scan WAL exists."""
    output = Path(getattr(config, "output_dir", ".") or ".")
    runtime = build_pipeline_authority_runtime(
        run_id=run_id,
        scan_wal=getattr(orchestrator, "_wal", None),
        raft_wal_dir=output / ".raft",
        spool_dir=output / ".qos",
        outbox_dir=output / ".outbox",
        total_budget=int(getattr(config, "global_budget_units", 10_000) or 10_000),
    )
    runtime.attach_to(orchestrator)
    return runtime


def apply_authority_recovery(runtime: PipelineAuthorityRuntime, reconstructed: Any) -> None:
    """Walk the PARTITION I35 plane after the replicated log is attached."""
    from src.core.frontier.event_delivery import get_delivery_ledger
    from src.core.frontier.recovery_protocol import (
        ObservedDurableState,
        RecoveryPhase,
        RecoveryPlane,
        rebuild_outbox_from_committed_entries,
        run_recovery_protocol,
    )

    log = getattr(runtime, "partition_log", None)
    outbox = getattr(runtime, "outbox", None)
    if log is None:
        return
    fsm_ids: set[str] = set()
    outbox_ids: set[str] = set()
    try:
        for entry in getattr(log, "entries", ()) or ():
            for evt in getattr(entry, "emitted_events", ()) or ():
                eid = str(getattr(evt, "event_id", "") or "")
                if eid:
                    fsm_ids.add(eid)
    except Exception:
        fsm_ids = set()
    try:
        if outbox is not None and hasattr(outbox, "read_all_events"):
            outbox_ids = {
                str(getattr(evt, "event_id", "") or "")
                for evt in outbox.read_all_events()
                if getattr(evt, "event_id", None)
            }
            outbox_ids.discard("")
    except Exception:
        outbox_ids = set()
    snapshot_index = 0
    checkpoint = getattr(reconstructed, "checkpoint", None)
    if checkpoint is not None:
        try:
            snapshot_index = int(getattr(checkpoint, "authoritative_log_index", 0) or 0)
        except (TypeError, ValueError):
            snapshot_index = 0
    commit_index = int(getattr(log, "commit_index", 0) or 0)
    from src.core.frontier.invariant_graph import collect_recovered_proof_artifacts

    payload = getattr(reconstructed, "context_payload", None) if reconstructed is not None else None
    artifacts = collect_recovered_proof_artifacts(payload=payload, wal=log)
    live_rev = artifacts.live_authority_revision
    placement = getattr(runtime, "placement", None)
    if placement is not None and hasattr(placement, "current_revision"):
        live_rev = str(placement.current_revision("P-0000") or live_rev)
    verdict = run_recovery_protocol(
        ObservedDurableState(
            plane=RecoveryPlane.PARTITION,
            snapshot_present=checkpoint is not None,
            wal_present=True,
            snapshot_schema_version=2,
            reader_schema_version=2,
            snapshot_log_index=snapshot_index,
            wal_commit_index=max(commit_index, snapshot_index),
            fsm_event_ids=frozenset(fsm_ids),
            outbox_event_ids=frozenset(outbox_ids),
            delivered_event_ids=frozenset(),
            recovered_tickets=artifacts.tickets,
            recovered_settlements=artifacts.settlements,
            recovered_identities=artifacts.identities,
            bus_emitted_without_outbox=artifacts.bus_emitted_without_outbox,
            live_authority_revision=live_rev,
        )
    )
    if verdict.rebuild_outbox:
        rebuild_outbox_from_committed_entries(getattr(log, "entries", ()) or (), outbox)
    if verdict.discarded_delivery_ids:
        get_delivery_ledger().discard_unknown([])
    if verdict.phase is RecoveryPhase.FAIL_CLOSED and reconstructed is not None:
        reconstructed.execute_stages = False
        reconstructed.recovery_phase = "fail_closed"
        reconstructed.remaining_stages = []


__all__ = [
    "apply_authority_recovery",
    "attach_pipeline_authority",
    "build_pipeline_authority_runtime",
    "resolve_execution_authorizer",
]
