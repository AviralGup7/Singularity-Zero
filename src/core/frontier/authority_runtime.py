"""In-process authority bundle constructed by the live CLI and dashboard.

Single-node Raft (quorum 1) plus GlobalBudget, HuntBudget adapter, policy
gate, QoS broker, PID, and bandit. Does not require a multi-host cluster.
Network transport is optional via ``transport=``.
"""

from __future__ import annotations

from contextvars import ContextVar
from pathlib import Path
from typing import Any

_CURRENT_HUNT_BUDGET: ContextVar[Any] = ContextVar("pipeline_hunt_budget", default=None)


def get_current_hunt_budget() -> Any | None:
    return _CURRENT_HUNT_BUDGET.get()


def set_current_hunt_budget(enforcer: Any | None) -> None:
    _CURRENT_HUNT_BUDGET.set(enforcer)

from src.core.frontier.global_coordination import GlobalBudgetAggregate, PlacementAuthority
from src.core.frontier.replicated_log import ReplicatedPartitionLog
from src.core.frontier.state_authority import SettlementCoordinator, StateAuthority
from src.decision.bayesian_bandit import BayesianParameterBandit
from src.decision.hunt_budget import HuntBudget, HuntBudgetEnforcer
from src.infrastructure.flow_control.pid_controller import AdaptivePIDController
from src.learning.policy_governance import PolicyGovernanceGate
from src.realtime.prioritized_broker import PrioritizedRealtimeBroker


class PipelineAuthorityRuntime:
    """Owns every authority object the live scan path is allowed to use."""

    def __init__(
        self,
        *,
        run_id: str,
        scan_wal: Any | None = None,
        raft_wal_dir: Path | str | None = None,
        spool_dir: Path | str | None = None,
        total_budget: int = 10_000,
        transport: Any | None = None,
        node_id: str = "",
    ) -> None:
        self.run_id = run_id
        self.scan_wal = scan_wal
        self.global_budget = GlobalBudgetAggregate(total_budget=int(total_budget))
        self.placement = PlacementAuthority()
        self.partition_log = ReplicatedPartitionLog(
            partition_id="P-0000",
            node_id=node_id or f"node-{run_id[:8]}",
            is_leader=True,
            wal_dir=raft_wal_dir,
            transport=transport,
        )
        self.state_authority = StateAuthority(wal=scan_wal)
        self.settlement = SettlementCoordinator(state_authority=self.state_authority)
        self.hunt_budget = HuntBudgetEnforcer(
            HuntBudget(max_requests=int(total_budget), label=run_id),
            global_budget=self.global_budget,
            partition_id="P-0000",
            run_id=run_id,
        )
        self.policy_gate = PolicyGovernanceGate(replicated_log=self.partition_log)
        self.qos = PrioritizedRealtimeBroker(
            spool_dir=str(spool_dir) if spool_dir is not None else None
        )
        self.pid = AdaptivePIDController()
        self.bandit = BayesianParameterBandit()

    def attach_to(self, orchestrator: Any) -> None:
        orchestrator._authority_runtime = self
        orchestrator._state_authority_instance = self.state_authority
        orchestrator._settlement_coordinator_instance = self.settlement
        orchestrator._hunt_budget_enforcer = self.hunt_budget
        orchestrator._partition_log = self.partition_log
        orchestrator._global_budget = self.global_budget
        orchestrator._policy_gate = self.policy_gate
        orchestrator._qos_broker = self.qos
        set_current_hunt_budget(self.hunt_budget)


def attach_pipeline_authority(orchestrator: Any, run_id: str, config: Any) -> PipelineAuthorityRuntime:
    """Build and bind authority objects after the scan WAL exists."""
    output = Path(getattr(config, "output_dir", ".") or ".")
    runtime = PipelineAuthorityRuntime(
        run_id=run_id,
        scan_wal=getattr(orchestrator, "_wal", None),
        raft_wal_dir=output / ".raft",
        spool_dir=output / ".qos",
        total_budget=int(getattr(config, "global_budget_units", 10_000) or 10_000),
    )
    runtime.attach_to(orchestrator)
    return runtime
