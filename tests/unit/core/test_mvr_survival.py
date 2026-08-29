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


if __name__ == "__main__":
    unittest.main()
