"""Construct the live CLI/dashboard authority bundle outside ``src.core``.

HuntBudget, the Bayesian bandit, and ExecutionAuthorizer live in
``src.decision`` and must not be imported by the core layer (architecture
purity). This module is the only factory the scan path should call.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

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
        total_budget=total_budget,
        transport=transport,
        node_id=node_id,
    )
    runtime.hunt_budget = HuntBudgetEnforcer(
        HuntBudget(max_requests=int(total_budget), label=run_id),
        global_budget=runtime.global_budget,
        partition_id="P-0000",
        run_id=run_id,
    )
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
        return runtime.authorizer
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
        total_budget=int(getattr(config, "global_budget_units", 10_000) or 10_000),
    )
    runtime.attach_to(orchestrator)
    return runtime


__all__ = [
    "attach_pipeline_authority",
    "build_pipeline_authority_runtime",
    "resolve_execution_authorizer",
]
