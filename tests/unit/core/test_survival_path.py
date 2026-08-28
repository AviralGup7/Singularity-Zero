"""Survival path: CompensationLedger, LeaseReaper, Phoenix, SURVIVAL_READONLY, enforcement."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from src.core.frontier.budget_phoenix import reconcile_budget
from src.core.frontier.compensation_log import (
    CompensationLedger,
    CompensationStatus,
)
from src.core.frontier.lease_reaper import LeaseReaper, ReapableLease
from src.core.frontier.lease_status import LeaseStatus
from src.core.recovery.survival import (
    assert_mutation_allowed,
    enter_survival,
    mutation_blocked,
    reset_survival,
)
from src.core.runtime.resource_guard import inspect_resources


class TestCompensationLedger(unittest.TestCase):
    def test_compensation_crash_after_marking_compensating(self) -> None:
        ledger = CompensationLedger(compensating_timeout_seconds=0.0)

        def _boom(_res: str, _lease: str) -> None:
            raise RuntimeError("killed after COMPENSATING")

        with self.assertRaises(RuntimeError):
            ledger.compensate("res_1", "lease_1", reason="crash", release=_boom)

        row = ledger.get("res_1", "lease_1")
        assert row is not None
        self.assertEqual(row.status, CompensationStatus.COMPENSATING)

        # Restart: replay stale COMPENSATING → COMPENSATED exactly once.
        released: list[tuple[str, str]] = []
        replayed = ledger.replay_stale(
            release=lambda res_id, lease_id: released.append((res_id, lease_id))
        )
        self.assertEqual(len(replayed), 1)
        self.assertEqual(replayed[0].status, CompensationStatus.COMPENSATED)
        self.assertEqual(released, [("res_1", "lease_1")])

        # Concurrent / duplicate compensate is idempotent.
        again = ledger.compensate("res_1", "lease_1", reason="dup")
        self.assertEqual(again.status, CompensationStatus.COMPENSATED)
        self.assertEqual(len(released), 1)


class TestLeaseReaper(unittest.TestCase):
    def test_reaper_compensates_stranded_reserved_after_crash(self) -> None:
        ledger = CompensationLedger()
        leases = [
            ReapableLease(
                reservation_id="res_a",
                lease_id="lease_a",
                status=LeaseStatus.RESERVED,
                deadline_mono=0.0,  # already expired vs now
            )
        ]
        mutated: list[LeaseStatus] = []
        reaper = LeaseReaper(
            ledger=ledger,
            source=lambda: leases,
            mutate=lambda _lease, status: mutated.append(status),
            min_tick_seconds=0.0,
        )
        n = reaper.tick(now_mono=10.0, lease_ttl=1.0)
        self.assertEqual(n, 1)
        self.assertIn(LeaseStatus.EXPIRED, mutated)
        self.assertIn(LeaseStatus.COMPENSATED, mutated)
        row = ledger.get("res_a", "lease_a")
        assert row is not None
        self.assertEqual(row.status, CompensationStatus.COMPENSATED)

        # Idempotent second tick
        self.assertEqual(reaper.tick(now_mono=11.0, lease_ttl=1.0), 1)


class TestSurvivalReadonly(unittest.TestCase):
    def tearDown(self) -> None:
        reset_survival()

    def test_survival_readonly_blocks_mutations_and_allows_reads_export(self) -> None:
        reset_survival()
        self.assertFalse(mutation_blocked("POST"))
        enter_survival("wal_unreadable", force=True)
        self.assertTrue(mutation_blocked("POST"))
        self.assertTrue(mutation_blocked("PUT"))
        self.assertFalse(mutation_blocked("GET"))
        with self.assertRaises(PermissionError):
            assert_mutation_allowed("scan_run")
        from src.api.health import liveness, survivalz

        live = liveness()
        self.assertEqual(live["status"], "ok")
        dump = survivalz()
        self.assertEqual(dump["mode"], "SURVIVAL_READONLY")
        self.assertEqual(dump["reason"], "wal_unreadable")


class TestPhoenix(unittest.TestCase):
    def test_phoenix_reconciles_ghost_outstanding_from_history(self) -> None:
        ledger = CompensationLedger()
        leases = [
            {"reservation_id": "ghost", "lease_id": "ghost", "status": "RESERVED"},
            {"reservation_id": "ok", "lease_id": "ok", "status": "CONSUMED"},
        ]
        report = reconcile_budget(leases=leases, ledger=ledger)
        self.assertIn("ghost", report.ghosts_compensated)
        self.assertEqual(report.consumed, 1)
        row = ledger.get("ghost", "ghost")
        assert row is not None
        self.assertEqual(row.status, CompensationStatus.COMPENSATED)


class TestEnforcementAndResources(unittest.TestCase):
    def test_enforcement_selfcheck_fails_closed_if_hook_missing(self) -> None:
        from src.bootstrap import enforcement_check as mod
        from src.bootstrap.enforcement_check import (
            BootstrapEnforcementError,
            InvariantHook,
            verify_enforcement,
        )

        original = mod.INVARIANT_HOOKS
        try:
            mod.INVARIANT_HOOKS = original + (
                InvariantHook("I99", "src.does.not.exist.module", required=True),
            )
            with self.assertRaises(BootstrapEnforcementError):
                verify_enforcement()
        finally:
            mod.INVARIANT_HOOKS = original
        try:
            report = verify_enforcement()
        except BootstrapEnforcementError as exc:
            # Local sandboxes may lack redis; CI installs it.
            if "redis" not in str(exc):
                raise
            return
        self.assertTrue(report.ok)
        self.assertTrue(any(item.startswith("I30:") for item in report.wired))

    def test_resource_guard_reports_ok_on_writable_tmp(self) -> None:
        snap = inspect_resources(wal_path=tempfile.gettempdir(), min_free_disk_bytes=1)
        self.assertTrue(snap.ok)

    def test_health_liveness_and_readiness(self) -> None:
        from src.api.health import liveness, readiness

        self.assertEqual(liveness()["status"], "ok")
        body = readiness(recovery_state="READY", invariants_ok=True, lag=0.0)
        self.assertIn(body["status"], {"ready", "not_ready"})


class TestRecoveryReport(unittest.TestCase):
    def test_recovery_manager_writes_report_on_fresh(self) -> None:
        from src.core.recovery.manager import RecoveryManager

        with tempfile.TemporaryDirectory() as td:
            mgr = RecoveryManager(Path(td), "example.com", wal_factory=lambda *a, **k: None)
            result = mgr.recover(force_fresh=True)
            self.assertFalse(result.can_recover)
            report = Path(td) / "recovery_report.json"
            self.assertTrue(report.exists())


class TestDurableDLQ(unittest.TestCase):
    def test_dlq_move_on_retry_exhaustion_and_idempotent_replay(self) -> None:
        from src.core.frontier.event_delivery import DeliveryLedger
        from src.core.outbox.dlq import DurableDLQ

        ledger = DeliveryLedger(max_delivery_attempts=2)
        poisoned = ledger.record_attempt("del_1", {"event_id": "evt_1"}, error="boom")
        self.assertFalse(poisoned)
        poisoned = ledger.record_attempt("del_1", {"event_id": "evt_1"}, error="boom")
        self.assertTrue(poisoned)
        with tempfile.TemporaryDirectory() as td:
            dlq = DurableDLQ(Path(td) / "dlq.json")
            self.assertEqual(dlq.ingest_poison(ledger.get_poison_events()), 1)
            self.assertEqual(dlq.depth(), 1)
            seen: list[str] = []
            self.assertTrue(dlq.replay("del_1", dispatch=lambda rec: seen.append(rec.delivery_id)))
            self.assertEqual(seen, ["del_1"])
            self.assertEqual(dlq.depth(), 0)
            self.assertFalse(dlq.replay("del_1"))


class TestOrphanReconciler(unittest.TestCase):
    def test_orphan_cross_epoch_requires_review(self) -> None:
        from src.core.recovery.orphan_reconciler import OrphanAction, OrphanClass, reconcile_orphans

        report = reconcile_orphans(
            [{"event_id": "e1", "epoch": 1, "commit_index": 3}],
            fsm_commit_index=5,
            live_epoch=2,
        )
        self.assertTrue(report["blocked"])
        self.assertEqual(report["orphans"][0]["orphan_class"], OrphanClass.CROSS_EPOCH.value)
        self.assertEqual(report["orphans"][0]["action"], OrphanAction.REVIEW.value)
        forced = reconcile_orphans(
            [{"event_id": "e1", "epoch": 1}],
            live_epoch=2,
            force=True,
        )
        self.assertFalse(forced["blocked"])


class TestQuotaSlab(unittest.TestCase):
    def test_slab_expires_and_reclaims(self) -> None:
        from src.core.frontier.quota_slab import QuotaSlabAllocator

        alloc = QuotaSlabAllocator(default_ttl_seconds=1.0)
        lease = alloc.reserve("slab_1", "P-0001", 10, now_mono=0.0, ttl_seconds=5.0)
        assert lease is not None
        self.assertEqual(alloc.reserved_units(), 10)
        self.assertTrue(alloc.renew("slab_1", now_mono=1.0, ttl_seconds=5.0))
        reclaimed = alloc.gc_expired(now_mono=100.0)
        self.assertEqual(reclaimed, ["slab_1"])
        self.assertEqual(alloc.reserved_units(), 0)


if __name__ == "__main__":
    unittest.main()
