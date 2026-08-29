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


if __name__ == "__main__":
    unittest.main()
