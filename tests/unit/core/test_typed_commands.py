"""Typed formal commands, upcasters, and HuntBudget → GlobalBudget adapter."""

from __future__ import annotations

from src.core.contracts.command_envelope import GLOBAL_UPCASTER_REGISTRY, CommandEnvelope
from src.core.frontier.commands import (
    allocate_sublease,
    reserve_global_budget,
    settlement_return,
)
from src.core.frontier.global_coordination import GlobalBudgetAggregate
from src.core.frontier.lease_status import LeaseStatus
from src.decision.hunt_budget import HuntBudget, HuntBudgetEnforcer


def test_typed_reserve_and_settle_via_apply_command() -> None:
    gb = GlobalBudgetAggregate(total_budget=500)
    env = reserve_global_budget(
        run_id="R1", partition_id="P-0001", units=80, sublease_id="sl_cmd"
    ).to_envelope()
    ok, code = gb.apply_command(env)
    assert ok
    assert code == "SUBLEASE_RESERVED"
    assert gb.outstanding_reserved == 80
    env2 = settlement_return(
        sublease_id="sl_cmd", units_consumed=30, units_returned=50
    ).to_envelope()
    ok, code = gb.apply_command(env2)
    assert ok
    assert gb.subleases["sl_cmd"].status == LeaseStatus.CONSUMED.value
    assert gb.verify_conservation()


def test_version_fence_on_global_budget() -> None:
    gb = GlobalBudgetAggregate(total_budget=100)
    env = reserve_global_budget(
        run_id="R", partition_id="P-0001", units=10, sublease_id="sl_v", command_id="c1"
    ).to_envelope()
    # force expected version mismatch
    env = CommandEnvelope(
        command_id=env.command_id,
        command_type=env.command_type,
        aggregate_id=env.aggregate_id,
        payload=dict(env.payload),
        correlation_id=env.correlation_id,
        causation_id=env.causation_id,
        expected_aggregate_version=99,
    )
    ok, msg = gb.apply_command(env)
    assert ok is False
    assert msg == "VERSION_CONFLICT"


def test_schema_upcaster_runs_on_command_load() -> None:
    GLOBAL_UPCASTER_REGISTRY.register(
        "TestOnlyUpcastCommand", 1, 2, lambda p: {**p, "upcasted": True}
    )
    env = CommandEnvelope.from_dict(
        {
            "command_id": "c-up",
            "command_type": "TestOnlyUpcastCommand",
            "aggregate_id": "sl",
            "payload": {"sublease_id": "sl", "units_allocated": 1, "run_id": "R"},
            "correlation_id": "x",
            "causation_id": "y",
            "schema_version": 1,
        }
    )
    assert env.payload.get("upcasted") is True
    assert env.schema_version == 2


def test_hunt_enforcer_routes_reservations_through_global_budget() -> None:
    gb = GlobalBudgetAggregate(total_budget=1000)
    enf = HuntBudgetEnforcer(
        HuntBudget(max_requests=100, label="nuclei"),
        global_budget=gb,
        partition_id="P-0001",
        run_id="scan1",
    )
    assert enf.reserve_requests(25) is True
    assert gb.outstanding_reserved == 25
    assert gb.verify_conservation()
    enf.commit_requests(25)
    assert gb.outstanding_reserved == 0
    assert gb.consumed == 25
    assert gb.verify_conservation()


def test_allocate_sublease_typed_roundtrip() -> None:
    cmd = allocate_sublease(
        sublease_id="sl_a", run_id="R", units_allocated=7, partition_id="P-0001"
    )
    env = cmd.to_envelope()
    assert env.command_type == "AllocateSubLeaseCommand"
    assert env.payload["units_allocated"] == 7
