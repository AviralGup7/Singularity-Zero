"""Architecture review P0 smoke tests (local, fast)."""

from __future__ import annotations

from types import SimpleNamespace


def test_ticket_consume_store_defaults_to_durable_path(tmp_path, monkeypatch):
    monkeypatch.delenv("TICKET_CONSUME_STORE", raising=False)
    monkeypatch.setenv("CSTP_DATA_DIR", str(tmp_path))
    from src.decision.authorization import ExecutionAuthorizer

    svc = ExecutionAuthorizer.__new__(ExecutionAuthorizer)
    path = svc._consumed_store_path()
    assert path == str(tmp_path / "consumed_tickets.jsonl")


def test_optional_needs_skipped_disabled_only_for_optional():
    from src.core.models.stage_status import StageStatus
    from src.pipeline.services.pipeline_orchestrator._graph_dsl import StageNode
    from src.pipeline.services.pipeline_orchestrator.actor_scheduler import ActorScheduler

    hard = StageNode(name="b", needs=("a",))
    soft = StageNode(name="c", needs=(), optional_needs=("a",))

    class _S:
        _JOIN_SINKS = frozenset()
        _completed: set[str] = set()
        _skipped: set[str] = set()
        _outcome = SimpleNamespace(skipped=set(), failed=set())
        _ctx = SimpleNamespace(
            result=SimpleNamespace(stage_status={"a": StageStatus.SKIPPED_DISABLED})
        )
        _need_met = ActorScheduler._need_met

    s = _S()
    assert s._need_met("a", hard) is False
    assert s._need_met("a", soft) is True


def test_require_kernel_sandbox_prod_default(monkeypatch):
    from src.sandbox.process_sandbox import ProcessSandbox

    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.delenv("REQUIRE_KERNEL_SANDBOX", raising=False)
    assert ProcessSandbox._env_requires_kernel_sandbox() is True

    monkeypatch.setenv("APP_ENV", "dev")
    assert ProcessSandbox._env_requires_kernel_sandbox() is False

    monkeypatch.setenv("REQUIRE_KERNEL_SANDBOX", "true")
    assert ProcessSandbox._env_requires_kernel_sandbox() is True


def test_lease_cross_boot_expires():
    from src.core.frontier.compensation_log import CompensationLedger
    from src.core.frontier.lease_reaper import LeaseReaper, ReapableLease
    from src.core.frontier.lease_status import LeaseStatus

    leases = [
        ReapableLease(
            reservation_id="r1",
            lease_id="l1",
            status=LeaseStatus.ACTIVE,
            deadline_mono=10**12,
            boot_id="other-boot",
        )
    ]
    ledger = CompensationLedger()
    seen: list[LeaseStatus] = []

    def mutate(lease: ReapableLease, status: LeaseStatus) -> None:
        seen.append(status)
        lease.status = status

    reaper = LeaseReaper(ledger=ledger, source=lambda: leases, mutate=mutate)
    n = reaper._reap(now_mono=0.0)
    assert n >= 1
    assert LeaseStatus.EXPIRED in seen or LeaseStatus.COMPENSATED in seen


def test_recovery_schema_newer_quarantines():
    from src.core.frontier.recovery_protocol import (
        CrashWindow,
        ObservedDurableState,
        RecoveryAction,
        RecoveryPlane,
        resolution_for,
        run_recovery_protocol,
    )

    res = resolution_for(CrashWindow.SCHEMA_NEWER_THAN_READER)
    assert res.frontier_action is RecoveryAction.QUARANTINE
    assert res.partition_action is RecoveryAction.FAIL_CLOSED

    observed = ObservedDurableState(
        plane=RecoveryPlane.FRONTIER,
        snapshot_present=True,
        wal_present=True,
        snapshot_schema_version=99,
        reader_schema_version=1,
        snapshot_log_index=1,
        wal_commit_index=1,
        snapshot_last_wal_id="w",
        wal_ids=("w",),
    )
    verdict = run_recovery_protocol(observed)
    assert verdict.action is RecoveryAction.QUARANTINE
    assert verdict.discard_snapshot is False


def test_settlement_intent_outbox_field():
    from src.core.frontier.state_authority import SettlementIntent

    intent = SettlementIntent(
        settlement_id="s1",
        execution_id="e1",
        outcome="COMMIT",
        budget_action="COMMIT",
        outbox_intent=True,
    )
    d = intent.to_dict()
    assert d["outbox_intent"] is True
    back = SettlementIntent.from_mapping(d)
    assert back.outbox_intent is True
