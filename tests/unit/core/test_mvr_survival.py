"""MVR survival: partial-success DAG, spill, frontier-only, DAG checkpoint, partial report."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

from src.core.models.stage_result import StageStatus
from src.pipeline.services.pipeline_orchestrator._graph_dsl import Graph, StageNode
from src.pipeline.services.pipeline_orchestrator.actor_scheduler import ActorScheduler


def _scheduler(
    nodes: tuple[StageNode, ...], *, remaining: list[str] | None = None
) -> ActorScheduler:
    graph = Graph(nodes=nodes)
    ctx = SimpleNamespace(
        run_id="run-mvr",
        result=SimpleNamespace(stage_status={}, module_metrics={}),
    )
    return ActorScheduler(
        graph,
        {},
        ctx=ctx,
        remaining_stages=remaining or [n.name for n in nodes],
        completed_stages=set(),
        orchestrator=SimpleNamespace(),
        args=SimpleNamespace(),
        config=SimpleNamespace(output_dir=None),
        scope_interceptor=None,
        nuclei_available=False,
        checkpoint_mgr=None,
        stage_checkpoint_guard=MagicMock(),
        progress_emitter=MagicMock(),
        error_emitter=MagicMock(),
    )


class TestPartialSuccessDag(unittest.TestCase):
    def test_non_critical_failure_becomes_degraded_and_continues(self) -> None:
        semgrep = StageNode(name="semgrep", needs=(), weight=1, critical=False, must_succeed=False)
        reporting = StageNode(name="reporting", needs=("semgrep",), weight=1)
        sched = _scheduler((semgrep, reporting))
        sched._ctx.result.stage_status["semgrep"] = StageStatus.FAILED.value
        sched._handle_completion(semgrep, None)
        self.assertEqual(sched._ctx.result.stage_status["semgrep"], StageStatus.DEGRADED.value)
        self.assertIn("semgrep", sched._completed)
        self.assertIsNone(sched._failed_critical)
        self.assertTrue(sched._need_met("semgrep", reporting))
        self.assertIn("error_summary", sched._ctx.result.module_metrics["semgrep"])

    def test_must_succeed_critical_keeps_failed_and_skips_dependents(self) -> None:
        live = StageNode(name="live_hosts", needs=(), weight=1, critical=True, must_succeed=True)
        active = StageNode(name="active_scan", needs=("live_hosts",), weight=1)
        sched = _scheduler((live, active))
        sched._ctx.result.stage_status["live_hosts"] = StageStatus.FAILED.value
        sched._handle_completion(live, None)
        self.assertEqual(sched._ctx.result.stage_status["live_hosts"], StageStatus.FAILED.value)
        self.assertIn("live_hosts", sched._outcome.failed)
        self.assertIn("active_scan", sched._outcome.skipped)

    def test_plugin_override_inherits_must_succeed(self) -> None:
        from src.pipeline.services.pipeline_orchestrator.graph_builder import build_pipeline_graph
        from src.pipeline.stage_registry import StageNodeDefinition

        plugin = StageNodeDefinition(
            name="live_hosts",
            needs=["subdomains"],
            weight=20,
            critical=True,
        )
        graph = build_pipeline_graph(registered_stages=[plugin])
        live = graph.require("live_hosts")
        self.assertTrue(live.must_succeed)
        self.assertEqual(live.weight, 20)


class TestFindingsSpill(unittest.TestCase):
    def test_spill_survives_and_merger_skips_existing(self) -> None:
        from src.core.findings.spill import FindingSpill, SpillMerger

        with tempfile.TemporaryDirectory() as td:
            spill = FindingSpill.for_run("run-1", td)
            rec = spill.append(
                {"title": "xss", "url": "https://example.test", "category": "xss"},
                stage="passive_scan",
                force=True,
            )
            assert rec is not None
            self.assertTrue(spill.path.exists())
            lines = spill.path.read_text(encoding="utf-8").strip().splitlines()
            self.assertEqual(len(lines), 1)
            pending = SpillMerger().reconcile("run-1", output_dir=td)
            self.assertEqual(len(pending), 1)
            again = SpillMerger().reconcile(
                "run-1", output_dir=td, existing_ids={rec["fingerprint"], rec["spill_id"]}
            )
            self.assertEqual(again, [])


class TestFrontierOnly(unittest.TestCase):
    def tearDown(self) -> None:
        from src.core.frontier.frontier_only import reset_frontier_only

        reset_frontier_only()

    def test_auto_off_does_not_enter(self) -> None:
        from src.core.frontier.frontier_only import enter_frontier_only, is_frontier_only

        enter_frontier_only("authority_unreachable")
        self.assertFalse(is_frontier_only())

    def test_force_blocks_settle_and_allows_discovery(self) -> None:
        from src.core.frontier.frontier_only import (
            enter_frontier_only,
            refuse_authoritative_settle,
            stage_allowed,
        )

        enter_frontier_only("authority_unreachable", force=True)
        self.assertTrue(refuse_authoritative_settle())
        self.assertTrue(stage_allowed("subdomains"))
        self.assertFalse(stage_allowed("nuclei"))


class TestDagCheckpoint(unittest.TestCase):
    def test_crashed_in_progress_detected(self) -> None:
        from src.core.checkpoint.dag_checkpoint import (
            DagCheckpoint,
            DagCheckpointStore,
            detect_crashed_runs,
        )

        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "run-x" / "dag_checkpoint.json"
            store = DagCheckpointStore(path)
            store.save(
                DagCheckpoint(
                    run_id="run-x",
                    status="RUNNING",
                    stage_status={"passive_scan": "RUNNING"},
                    clean_exit=False,
                )
            )
            crashed = detect_crashed_runs(td)
            self.assertEqual(len(crashed), 1)
            self.assertTrue(crashed[0].is_crashed_in_progress())
            store.mark_clean_exit(crashed[0], status="STOPPED")
            self.assertEqual(detect_crashed_runs(td), [])


class TestPartialReport(unittest.TestCase):
    def test_emit_partial_writes_json_and_sarif(self) -> None:
        from src.reporting.partial import emit_partial_report

        ctx = SimpleNamespace(
            run_id="run-p",
            result=SimpleNamespace(
                stage_status={"passive_scan": "COMPLETED"},
                findings=[
                    {"title": "open-redirect", "url": "https://example.test", "severity": "low"}
                ],
            ),
        )
        with tempfile.TemporaryDirectory() as td:
            result = emit_partial_report("run-p", "sigint", output_dir=td, ctx=ctx)
            self.assertGreaterEqual(result.findings_emitted, 1)
            json_path = Path(td) / "run-p" / "partial" / "report_partial.json"
            self.assertTrue(json_path.exists())
            payload = json.loads(json_path.read_text(encoding="utf-8"))
            self.assertTrue(payload["partial"])
            self.assertEqual(payload["reason"], "sigint")
            self.assertTrue((Path(td) / "run-p" / "partial" / "report_partial.sarif").exists())


class TestPressureAndReplay(unittest.TestCase):
    def test_classify_pressure_critical(self) -> None:
        from src.core.runtime.resource_guard import PressureLevel, classify_pressure

        self.assertEqual(classify_pressure(disk_pct=50), PressureLevel.OK)
        self.assertEqual(classify_pressure(disk_pct=86), PressureLevel.WARN)
        self.assertEqual(classify_pressure(disk_pct=93), PressureLevel.PRESSURE)
        self.assertEqual(classify_pressure(disk_pct=96), PressureLevel.CRITICAL)

    def test_merge_queue_cursor(self) -> None:
        from src.core.frontier.merge_queue import FrontierMergeQueue

        with tempfile.TemporaryDirectory() as td:
            q = FrontierMergeQueue(Path(td) / "q.jsonl")
            self.assertTrue(q.append({"id": "a"}))
            self.assertTrue(q.append({"id": "b"}))
            first = q.pending()
            self.assertEqual(len(first), 2)
            second = q.pending()
            self.assertEqual(second, [])

    def test_dlq_append_record_not_enqueue_name(self) -> None:
        import ast

        tree = ast.parse(Path("src/core/outbox/dlq.py").read_text(encoding="utf-8"))
        names: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and node.attr in {"enqueue", "enqueue_task"}:
                names.append(node.attr)
        self.assertEqual(names, [])


class TestPlanRemainders(unittest.TestCase):
    def test_finding_created_requires_wal_id(self) -> None:
        from src.core.frontier.finding_created import FindingCreated

        with self.assertRaises(ValueError):
            FindingCreated(wal_id="", settlement_id="s", event_id="e", finding={})
        event = FindingCreated(wal_id="wal_1", settlement_id="stl_1", event_id="evt_1", finding={})
        self.assertEqual(event.wal_id, "wal_1")

    def test_graph_gen_id_order_independent_and_mismatch(self) -> None:
        from src.pipeline.graph_identity import (
            GraphGenerationMismatch,
            assert_graph_generation,
            graph_gen_id,
        )
        from src.pipeline.services.pipeline_orchestrator._graph_dsl import Graph, StageNode

        a = StageNode(name="a", needs=(), weight=1)
        b = StageNode(name="b", needs=("a",), weight=2)
        g1 = Graph(nodes=(a, b))
        g2 = Graph(nodes=(b, a))
        self.assertEqual(graph_gen_id(g1), graph_gen_id(g2))
        assert_graph_generation(graph_gen_id(g1), graph_gen_id(g2))
        with self.assertRaises(GraphGenerationMismatch):
            assert_graph_generation("deadbeef" * 4, graph_gen_id(g1))

    def test_ticket_already_consumed_raises(self) -> None:
        from src.decision.authorization import ExecutionAuthorizer, TicketAlreadyConsumedError
        from src.decision.hunt_budget import HuntBudget, HuntBudgetEnforcer
        from src.decision.models import ExecutionRequest, TargetSpec

        auth = ExecutionAuthorizer(
            budget_enforcer=HuntBudgetEnforcer(HuntBudget(max_requests=10), label="t")
        )
        ticket = auth.authorize(
            ExecutionRequest(
                request_id="r", tenant_id="t", target=TargetSpec(host="example.com"), stage="s"
            )
        )
        self.assertTrue(auth.consume_ticket(ticket))
        with self.assertRaises(TicketAlreadyConsumedError):
            auth.consume_ticket(ticket)

    def test_dlq_cli_list_and_purge(self) -> None:
        from src.cli.commands.system import handle_dlq
        from src.core.outbox.dlq import DLQRecord, DurableDLQ

        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "dlq.json"
            dlq = DurableDLQ(path)
            dlq.append_record(DLQRecord(delivery_id="d1", event_id="e1", reason="test"))
            ns = SimpleNamespace(
                dlq_action="list",
                dlq_path=str(path),
                delivery_id="",
                all=False,
                older_than=1.0,
                force=False,
            )
            self.assertEqual(handle_dlq(ns), 0)
            ns.dlq_action = "purge"
            ns.force = True
            ns.older_than = 0.0
            self.assertEqual(handle_dlq(ns), 0)

    def test_spill_first_under_pressure(self) -> None:
        import os

        from src.core.runtime.resource_guard import (
            PressureLevel,
            set_pressure_level,
            spill_first_active,
        )

        set_pressure_level(PressureLevel.OK)
        os.environ.pop("SPILL_FIRST", None)
        self.assertFalse(spill_first_active())
        set_pressure_level(PressureLevel.PRESSURE)
        self.assertTrue(spill_first_active())
        set_pressure_level(PressureLevel.OK)

    def test_worker_dead_heartbeat(self) -> None:
        from src.core.checkpoint.dag_checkpoint import DagCheckpoint

        snap = DagCheckpoint(run_id="r", status="RUNNING", last_heartbeat_ts=1.0, clean_exit=False)
        self.assertTrue(snap.is_worker_dead(now=200.0, dead_after_s=120.0))
        snap.clean_exit = True
        self.assertFalse(snap.is_worker_dead(now=200.0, dead_after_s=120.0))

    def test_dag_checkpoint_roundtrips_graph_gen_id(self) -> None:
        from src.core.checkpoint.dag_checkpoint import DagCheckpoint, DagCheckpointStore

        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "dag_checkpoint.json"
            store = DagCheckpointStore(path)
            store.save(DagCheckpoint(run_id="run-g", graph_gen_id="abc123", status="RUNNING"))
            loaded = store.load()
            assert loaded is not None
            self.assertEqual(loaded.graph_gen_id, "abc123")

    def test_choose_lkg_snapshot_max_commit_then_term(self) -> None:
        from src.core.frontier.budget_phoenix import choose_lkg_snapshot

        chosen = choose_lkg_snapshot(
            [
                {"id": "old", "commitIndex": 3, "term": 9, "verified": True},
                {"id": "best", "commitIndex": 10, "term": 1, "verified": True},
                {"id": "unverified", "commitIndex": 99, "term": 99, "verified": False},
                {"id": "tie_term", "commitIndex": 10, "term": 4, "verified": True},
            ]
        )
        assert chosen is not None
        self.assertEqual(chosen["id"], "tie_term")
        self.assertIsNone(choose_lkg_snapshot([]))

    def test_replay_finding_dispatch_requires_hmac(self) -> None:
        from src.core.events.event_bus import EventType, get_event_bus, reset_event_bus
        from src.core.frontier.event_delivery import replay_finding_dispatch
        from src.core.frontier.settlement_receipt import stamp_finding_receipt

        reset_event_bus()
        bus = get_event_bus()
        seen: list[object] = []
        bus.subscribe(EventType.FINDING_CREATED, lambda event: seen.append(event))
        self.assertFalse(replay_finding_dispatch({"wal_id": "wal_1", "authoritative": True}))
        self.assertEqual(seen, [])
        receipt = stamp_finding_receipt(
            wal_id="wal_replay", settlement_id="stl_r", command_id="cmd_r"
        )
        self.assertTrue(replay_finding_dispatch({**receipt, "event_id": "evt_r"}))
        self.assertEqual(len(seen), 1)
        reset_event_bus()

    def test_tool_policy_retry_settings(self) -> None:
        from src.pipeline.tool_policy import ToolPolicy, is_unavailable_error

        settings = ToolPolicy(retries=4, timeout_s=30.0).as_retry_settings()
        self.assertEqual(settings["retry_attempts"], 4)
        self.assertEqual(settings["timeout_seconds"], 30.0)
        self.assertTrue(is_unavailable_error(FileNotFoundError("nuclei")))

    def test_consumed_tickets_roundtrip_on_dag_checkpoint(self) -> None:
        from src.core.checkpoint.dag_checkpoint import DagCheckpoint, DagCheckpointStore
        from src.decision.authorization import ExecutionAuthorizer
        from src.decision.hunt_budget import HuntBudget, HuntBudgetEnforcer

        auth = ExecutionAuthorizer(
            budget_enforcer=HuntBudgetEnforcer(HuntBudget(max_requests=10), label="t")
        )
        auth.remember_consumed(["tkt-a", "tkt-b"])
        self.assertEqual(auth.consumed_ticket_ids(), frozenset({"tkt-a", "tkt-b"}))
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "dag_checkpoint.json"
            store = DagCheckpointStore(path)
            store.save(
                DagCheckpoint(
                    run_id="run-t",
                    consumed_ticket_ids=sorted(auth.consumed_ticket_ids()),
                )
            )
            loaded = store.load()
            assert loaded is not None
            self.assertEqual(loaded.consumed_ticket_ids, ["tkt-a", "tkt-b"])
            other = ExecutionAuthorizer(
                budget_enforcer=HuntBudgetEnforcer(HuntBudget(max_requests=10), label="t")
            )
            other.remember_consumed(loaded.consumed_ticket_ids)
            self.assertIn("tkt-a", other.consumed_ticket_ids())

    def test_production_signing_key_required(self) -> None:
        import os

        from src.core.frontier.receipt_crypto import (
            PersistentSigningKeyRequired,
            require_persistent_signing_key,
        )

        old_env = os.environ.get("APP_ENV")
        old_a = os.environ.get("AUTHORITY_SIGNING_KEY")
        old_s = os.environ.get("APP_SECRET_KEY")
        try:
            os.environ["APP_ENV"] = "production"
            os.environ.pop("AUTHORITY_SIGNING_KEY", None)
            os.environ.pop("APP_SECRET_KEY", None)
            with self.assertRaises(PersistentSigningKeyRequired):
                require_persistent_signing_key()
            os.environ["APP_ENV"] = "development"
            require_persistent_signing_key()
        finally:
            if old_env is None:
                os.environ.pop("APP_ENV", None)
            else:
                os.environ["APP_ENV"] = old_env
            if old_a is None:
                os.environ.pop("AUTHORITY_SIGNING_KEY", None)
            else:
                os.environ["AUTHORITY_SIGNING_KEY"] = old_a
            if old_s is None:
                os.environ.pop("APP_SECRET_KEY", None)
            else:
                os.environ["APP_SECRET_KEY"] = old_s

    def test_graph_gen_id_ignores_tool_pruning(self) -> None:
        from src.pipeline.graph_identity import graph_gen_id
        from src.pipeline.services.pipeline_orchestrator.graph_builder import build_pipeline_graph

        full = build_pipeline_graph(tool_status={"nuclei": True, "semgrep": True})
        pruned = build_pipeline_graph(tool_status={"nuclei": False, "semgrep": True})
        self.assertEqual(graph_gen_id(full), graph_gen_id(pruned))
        self.assertTrue(pruned.declared_gen_id)
        names_full = {n.name for n in full.nodes}
        names_pruned = {n.name for n in pruned.nodes}
        if "nuclei" in names_full:
            self.assertNotIn("nuclei", names_pruned)

    def test_cas_lease_fence_refuses_stale(self) -> None:
        from src.core.frontier.lease_status import (
            LeaseStatus,
            StaleLeaseFenceError,
            cas_lease_status,
        )

        cas_lease_status(LeaseStatus.ACTIVE, LeaseStatus.CONSUMED, fence=1, expected_fence=1)
        with self.assertRaises(StaleLeaseFenceError):
            cas_lease_status(LeaseStatus.ACTIVE, LeaseStatus.EXPIRED, fence=1, expected_fence=2)

    def test_activate_ownership_requires_replica_catch_up(self) -> None:
        from src.core.frontier.global_coordination import PlacementAuthority

        pa = PlacementAuthority(home_region="local")
        epoch = pa.initiate_transfer("agg", "P-0000", "P-0001", to_region="other")
        self.assertFalse(
            pa.activate_ownership(
                "agg",
                "P-0001",
                epoch,
                replica_applied_offset=3,
                source_committed_offset=10,
            )
        )
        self.assertTrue(
            pa.activate_ownership(
                "agg",
                "P-0001",
                epoch,
                replica_applied_offset=10,
                source_committed_offset=10,
            )
        )

    def test_tenant_isolation_i38(self) -> None:
        from src.core.frontier.tenant_isolation import TenantIsolationError, assert_tenant_scope

        assert_tenant_scope(resource_tenant="t1", actor_tenant="t1")
        with self.assertRaises(TenantIsolationError):
            assert_tenant_scope(resource_tenant="t1", actor_tenant="t2")
        with self.assertRaises(TenantIsolationError):
            assert_tenant_scope(resource_tenant="t1", actor_tenant="")

    def test_budget_mode_transition_atomic(self) -> None:
        from src.core.frontier.quota_slab import (
            BudgetModeTransitionError,
            transition_accounting_mode,
        )

        snap = transition_accounting_mode(
            total=100, consumed=10, outstanding=20, available=70, slab_units=15, to_multi_raft=True
        )
        self.assertEqual(snap["slab_reserved"], 15)
        self.assertEqual(snap["available"], 55)
        self.assertEqual(
            snap["consumed"] + snap["outstanding"] + snap["slab_reserved"] + snap["available"],
            100,
        )
        back = transition_accounting_mode(
            total=snap["total"],
            consumed=snap["consumed"],
            outstanding=snap["outstanding"],
            available=snap["available"],
            slab_reserved=snap["slab_reserved"],
            to_multi_raft=False,
        )
        self.assertEqual(back["slab_reserved"], 0)
        self.assertEqual(back["available"], 70)
        with self.assertRaises(BudgetModeTransitionError):
            transition_accounting_mode(
                total=100, consumed=10, outstanding=20, available=70, slab_units=80
            )

    def test_skip_pending_unblocks_join_sink(self) -> None:
        from src.core.models.stage_status import StageStatus
        from src.pipeline.services.pipeline_orchestrator._graph_dsl import StageNode

        nuclei = StageNode(name="nuclei", needs=(), weight=1)
        reporting = StageNode(name="reporting", needs=("nuclei",), weight=1)
        sched = _scheduler((nuclei, reporting))
        sched._ctx.result.stage_status["nuclei"] = StageStatus.PENDING.value
        sched._skip_remaining_keep_sinks(reason="resource_guard_critical")
        self.assertEqual(
            sched._ctx.result.stage_status["nuclei"], StageStatus.SKIPPED_DISABLED.value
        )
        self.assertTrue(sched._need_met("nuclei", reporting))

    def test_core_recovery_manager_does_not_import_reporting(self) -> None:
        import ast

        tree = ast.parse(Path("src/core/recovery/manager.py").read_text(encoding="utf-8"))
        modules: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                modules.append(node.module)
            elif isinstance(node, ast.Import):
                modules.extend(alias.name for alias in node.names)
        self.assertFalse(any(m.startswith("src.reporting") for m in modules))


if __name__ == "__main__":
    unittest.main()
