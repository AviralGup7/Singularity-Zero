"""Integration tests verifying deterministic log replay, schema upcasting, and projection recovery."""

from src.core.contracts.command_envelope import GLOBAL_UPCASTER_REGISTRY
from src.core.frontier.replay_engine import DeterministicReplayEngine
from src.core.frontier.state import NeuralState
from src.core.frontier.state_authority import (
    BudgetProjection,
    FindingsProjection,
    LeaseProjection,
    SettlementIntent,
    SettlementProjectionEngine,
    StateProjection,
)
from src.decision.hunt_budget import HuntBudget, HuntBudgetEnforcer


def test_deterministic_replay_and_projection_recovery() -> None:
    # 1. Prepare projection engine
    state = NeuralState()
    enforcer = HuntBudgetEnforcer(HuntBudget(max_requests=100))
    state_proj = StateProjection(state)
    budget_proj = BudgetProjection(enforcer)
    lease_proj = LeaseProjection()
    findings_proj = FindingsProjection()

    proj_engine = SettlementProjectionEngine(
        state_projection=state_proj,
        budget_projection=budget_proj,
        lease_projection=lease_proj,
        findings_projection=findings_proj,
    )
    replay_engine = DeterministicReplayEngine(proj_engine)

    # 2. Build 10 synthetic WAL entries
    wal_entries = []
    for i in range(10):
        intent = SettlementIntent(
            settlement_id=f"stl_{i}",
            execution_id=f"exec_{i}",
            candidate_id=f"cand_{i}",
            lease_id=f"lease_{i}",
            outcome="COMPLETED",
            state_delta={
                "urls": [f"https://example.com/endpoint_{i}"],
                "findings": [
                    {
                        "category": "xss",
                        "title": "Cross-Site Scripting",
                        "url": f"https://example.com/endpoint_{i}",
                        "severity": "medium",
                        "confidence": 0.85,
                    }
                ],
            },
            budget_action="COMMIT",
            budget_request_count=1,
            lease_action="ACK",
            created_at=1700000000.0 + i,
        )
        entry = intent.to_dict()
        entry["log_offset"] = i
        entry["_wal_id"] = f"wal_offset_{i}"
        wal_entries.append(entry)

    # 3. Replay from WAL
    summary = replay_engine.replay_log_entries(wal_entries)
    assert summary.invariants_valid is True
    assert summary.total_events_read == 10
    assert summary.applied_state_events == 10
    assert summary.applied_budget_events == 10
    assert summary.applied_findings_events == 10

    # 4. Verify reconstructed state
    assert enforcer.consumed_requests == 10
    assert len(findings_proj.findings) == 10
    assert "https://example.com/endpoint_0" in state.urls


def test_schema_upcaster_migration() -> None:
    # Register an upcaster from schema_version 1 -> 2
    def _upcast_finding_payload(payload: dict) -> dict:
        p = dict(payload)
        p["upcasted_marker"] = True
        return p

    GLOBAL_UPCASTER_REGISTRY.register(
        event_type="ExecutionSettled.v1",
        from_version=1,
        to_version=2,
        fn=_upcast_finding_payload,
    )

    old_event = {
        "event_type": "ExecutionSettled.v1",
        "schema_version": 1,
        "payload": {"finding_id": "f100"},
    }

    upcasted = GLOBAL_UPCASTER_REGISTRY.upcast(old_event)
    assert upcasted["schema_version"] == 2
    assert upcasted["payload"]["upcasted_marker"] is True
