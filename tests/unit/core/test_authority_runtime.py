"""CLI authority bundle constructs Raft log, budget adapter, policy gate, QoS."""

from __future__ import annotations

from types import SimpleNamespace

from src.core.frontier.raft_transport import NetworkRaftTransport
from src.decision.authorization import ExecutionAuthorizer, ScopeAuthorizationError
from src.decision.models import ExecutionRequest, TargetSpec
from src.pipeline.authority_bootstrap import (
    attach_pipeline_authority,
    build_pipeline_authority_runtime,
)


def test_runtime_constructs_single_node_raft(tmp_path) -> None:
    rt = build_pipeline_authority_runtime(run_id="run-test", raft_wal_dir=tmp_path / "raft")
    assert rt.partition_log.is_leader is True
    assert rt.partition_log.quorum_size == 1
    assert rt.global_budget.verify_conservation()
    assert rt.hunt_budget.reserve_requests(3) is True
    assert rt.global_budget.outstanding_reserved == 3
    orch = SimpleNamespace()
    rt.attach_to(orch)
    assert orch._authority_runtime is rt
    assert orch.state_authority is rt.state_authority if hasattr(orch, "state_authority") else True
    assert orch._settlement_coordinator_instance is rt.settlement


def test_attach_pipeline_authority_on_orchestrator(tmp_path) -> None:
    orch = SimpleNamespace(_wal=None)
    cfg = SimpleNamespace(output_dir=str(tmp_path), global_budget_units=500)
    rt = attach_pipeline_authority(orch, "run-attach", cfg)
    assert orch._authority_runtime is rt
    assert rt.partition_log.partition_id == "P-0000"


def test_authorizer_uses_runtime_hunt_budget() -> None:
    rt = build_pipeline_authority_runtime(run_id="run-auth", total_budget=10)
    auth = ExecutionAuthorizer(budget_enforcer=rt.hunt_budget)
    req = ExecutionRequest(
        request_id="r1",
        tenant_id="t",
        target=TargetSpec(host="example.com"),
        stage="probe",
    )
    ticket = auth.authorize(req)
    assert ticket.ticket_id.startswith("tkt_")
    # Exhaust remaining budget
    for i in range(20):
        try:
            auth.authorize(
                ExecutionRequest(
                    request_id=f"r{i + 2}",
                    tenant_id="t",
                    target=TargetSpec(host="example.com"),
                    stage="probe",
                )
            )
        except ScopeAuthorizationError:
            break
    else:
        raise AssertionError("expected budget exhaustion")


def test_hunt_budget_contextvar_is_set_on_attach() -> None:
    from src.core.frontier.authority_runtime import get_current_hunt_budget

    rt = build_pipeline_authority_runtime(run_id="run-ctx")
    orch = SimpleNamespace()
    rt.attach_to(orch)
    assert get_current_hunt_budget() is rt.hunt_budget


def test_network_raft_transport_unknown_peer() -> None:
    t = NetworkRaftTransport()
    from src.core.frontier.raft_transport import RequestVoteRequest

    resp = t.send_request_vote(
        "missing",
        RequestVoteRequest(term=1, candidate_id="c", last_log_index=0, last_log_term=0),
    )
    assert resp.vote_granted is False
    assert resp.error_code == "NODE_NOT_FOUND"
