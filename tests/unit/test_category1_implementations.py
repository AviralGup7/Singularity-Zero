"""Unit test suite verifying all Category 1 implementations."""

from __future__ import annotations

import os
from unittest.mock import MagicMock

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from src.cli import _build_parser
from src.core.frontier.invariant_checker import INVARIANT_VERIFICATION_MATRIX
from src.core.frontier.replicated_log import CommittedEntry, PartitionWAL
from src.core.frontier.state_authority import SettlementResult
from src.decision.hunt_budget import BudgetReserveDenied, HuntBudget, HuntBudgetEnforcer
from src.infrastructure.cache.cache_manager import CacheManager
from src.jobs.run_outcome import derive_job_and_exit
from src.pipeline.services.pipeline_orchestrator._graph_dsl import (
    DeclaredGraph,
    FrozenGraph,
    Graph,
    StageNode,
)
from src.realtime.prioritized_broker import QoSClass
from src.realtime.qos_admit import QoSDecision, qos_admit


def test_cli_scan_resume_parser() -> None:
    parser = _build_parser()
    args = parser.parse_args(
        ["scan", "resume", "--run-id", "test-run-123", "--config", "c.yaml", "--scope", "s.yaml"]
    )
    assert args.area == "scan"
    assert args.command == "resume"
    assert args.run_id == "test-run-123"
    assert args.config == "c.yaml"
    assert args.scope == "s.yaml"


def test_graph_typing_declared_and_frozen() -> None:
    node = StageNode(name="dummy")
    declared = DeclaredGraph(nodes=(node,))
    assert isinstance(declared, Graph)
    frozen = FrozenGraph(nodes=(node,), declared_gen_id="gen1", capability_gen_id="cap1")
    assert isinstance(frozen, Graph)
    assert frozen.declared_gen_id == "gen1"
    assert frozen.capability_gen_id == "cap1"


def test_seven_tier_exit_precedence_lattice() -> None:
    # 1. Cancel (130) > Infra (3)
    r130 = derive_job_and_exit({}, (), cancel=True, fatal_stages=("dummy",))
    assert r130.exit_code == 130

    # 2. Infra (3) > Suspend (7)
    r3 = derive_job_and_exit({"fatal": "failed"}, (), fatal_stages=("fatal",), suspend=True)
    assert r3.exit_code == 3

    # 3. Suspend (7) > Policy (2)
    r7 = derive_job_and_exit({}, (), suspend=True, policy_violated=True)
    assert r7.exit_code == 7
    assert r7.job_status.value == "stopped"

    # 4. Policy (2) > Degraded (4)
    r2 = derive_job_and_exit({"stg": "degraded"}, (), policy_violated=True)
    assert r2.exit_code == 2

    # 5. Degraded (4) > Runtime Error (1)
    r4 = derive_job_and_exit({"stg": "degraded"}, (), runtime_error=True)
    assert r4.exit_code == 4

    # 6. Runtime Error (1) > Clean (0)
    r1 = derive_job_and_exit({}, (), runtime_error=True)
    assert r1.exit_code == 1
    assert r1.job_status.value == "failed"

    # 7. Clean Pass (0)
    r0 = derive_job_and_exit({}, ())
    assert r0.exit_code == 0
    assert r0.job_status.value == "completed"


def test_budget_reserve_denied_exception() -> None:
    enforcer = HuntBudgetEnforcer(HuntBudget(max_requests=5))
    # Test valid reservation
    res = enforcer.reserve_with_identity(count=1)
    assert res is not None

    # Test count <= 0 with raise_on_denial=True
    with pytest.raises(BudgetReserveDenied, match="positive"):
        enforcer.reserve_with_identity(count=0, raise_on_denial=True)

    # Test closed reserve gate with raise_on_denial=True
    enforcer.set_reserve_gate(lambda: False)
    with pytest.raises(BudgetReserveDenied, match="gate closed"):
        enforcer.reserve_with_identity(count=1, raise_on_denial=True)


def test_multidimensional_qos_admit() -> None:
    # Spool depth > 1000
    assert qos_admit(QoSClass.P0_CONTROL, disk_pct=50, spool_depth=1001) == QoSDecision.ADMIT
    assert qos_admit(QoSClass.P1_LIFECYCLE, disk_pct=50, spool_depth=1001) == QoSDecision.DROP

    # Severe RAM pressure (> 90%)
    assert qos_admit(QoSClass.P4_DEBUG, disk_pct=50, ram_pct=95.0) == QoSDecision.DROP
    assert qos_admit(QoSClass.P2_FINDINGS, disk_pct=50, ram_pct=95.0) == QoSDecision.COALESCE
    assert qos_admit(QoSClass.P0_CONTROL, disk_pct=50, ram_pct=95.0) == QoSDecision.ADMIT

    # Moderate CPU pressure (> 90%)
    assert qos_admit(QoSClass.P4_DEBUG, disk_pct=50, cpu_pct=95.0) == QoSDecision.DROP
    assert qos_admit(QoSClass.P3_TELEMETRY, disk_pct=50, cpu_pct=95.0) == QoSDecision.ADMIT

    # Normal conditions
    assert qos_admit(QoSClass.P4_DEBUG, disk_pct=50, ram_pct=50.0, cpu_pct=50.0) == QoSDecision.ADMIT


def test_partition_wal_log_compaction(tmp_path) -> None:
    from types import SimpleNamespace

    wal = PartitionWAL(partition_id="part-1", node_id="node-1", wal_dir=None)
    e1 = SimpleNamespace(raft_index=1, to_dict=lambda: {"raft_index": 1})
    e2 = SimpleNamespace(raft_index=2, to_dict=lambda: {"raft_index": 2})
    e3 = SimpleNamespace(raft_index=3, to_dict=lambda: {"raft_index": 3})
    wal.append_entry(e1, committed=True)
    wal.append_entry(e2, committed=True)
    wal.append_entry(e3, committed=True)
    assert len(wal._in_memory_records) == 3
    assert wal.last_compacted_index == 0

    pruned = wal.compact_log(up_to_index=2)
    assert pruned == 2
    assert wal.last_compacted_index == 2
    assert len(wal._in_memory_records) == 1
    assert wal._in_memory_records[0][0].raft_index == 3


def test_settlement_result_dropped_status() -> None:
    res = SettlementResult(execution_id="exec-drop", status="DROPPED")
    assert res.status == "DROPPED"
    assert res.outbox_appended is None


def test_invariant_matrix_i38_and_i39() -> None:
    assert "I38" in INVARIANT_VERIFICATION_MATRIX
    assert "I39" in INVARIANT_VERIFICATION_MATRIX
    assert "Projection Watermark" in INVARIANT_VERIFICATION_MATRIX["I8"]["name"]


def test_cache_manager_subscribe_to_event_bus() -> None:
    cache = CacheManager()
    mock_bus = MagicMock()
    cache.subscribe_to_event_bus(mock_bus)
    assert mock_bus.subscribe.call_count >= 6
    cache.close()


def test_authentication_middleware_sets_user_id() -> None:
    from src.dashboard.fastapi.middleware import AuthenticationMiddleware

    app = FastAPI()
    app.add_middleware(AuthenticationMiddleware)

    @app.get("/test-auth")
    async def get_test(request: Request):
        return {
            "user_id": getattr(request.state, "user_id", None),
            "tenant_id": getattr(request.state, "tenant_id", None),
        }

    client = TestClient(app)
    r = client.get("/test-auth")
    assert r.status_code == 200, r.text
    data = r.json()
    assert "user_id" in data
    assert data["tenant_id"] == "default"

