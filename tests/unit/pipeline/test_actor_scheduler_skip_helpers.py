"""Planner skip helpers must exist and emit explicit skipped events."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from src.core.models.stage_result import StageStatus
from src.pipeline.services.pipeline_orchestrator._graph_dsl import Graph, StageNode
from src.pipeline.services.pipeline_orchestrator.actor_scheduler import ActorScheduler


def _scheduler() -> ActorScheduler:
    node = StageNode(name="waf", needs=(), weight=1)
    graph = Graph(nodes=(node,))
    ctx = SimpleNamespace(
        result=SimpleNamespace(
            stage_status={},
            module_metrics={"waf": {"status": "skipped", "reason": "probabilistic_skip_low_confidence"}},
        )
    )
    return ActorScheduler(
        graph,
        {},
        ctx=ctx,
        remaining_stages=["waf"],
        completed_stages=set(),
        orchestrator=SimpleNamespace(),
        args=SimpleNamespace(),
        config=SimpleNamespace(),
        scope_interceptor=None,
        nuclei_available=False,
        checkpoint_mgr=None,
        stage_checkpoint_guard=MagicMock(),
        progress_emitter=MagicMock(),
        error_emitter=MagicMock(),
    )


def test_planner_skip_reason_reads_module_metrics() -> None:
    scheduler = _scheduler()
    assert scheduler._planner_skip_reason("waf") == "probabilistic_skip_low_confidence"
    assert scheduler._planner_skip_reason("unknown") == "planner_dropped"


def test_mark_skipped_by_name_emits_skip_and_does_not_crash() -> None:
    scheduler = _scheduler()
    with patch(
        "src.pipeline.services.pipeline_orchestrator.actor_scheduler.emit_stage_skipped"
    ) as emit:
        scheduler._mark_skipped_by_name("waf", reason="planner_dropped")
        emit.assert_called_once_with("waf", "planner_dropped")
    assert "waf" in scheduler._outcome.skipped
    assert scheduler._ctx.result.stage_status["waf"] == StageStatus.SKIPPED.value


def test_mark_skipped_emits_reason() -> None:
    scheduler = _scheduler()
    node = scheduler._graph.nodes[0]
    with patch(
        "src.pipeline.services.pipeline_orchestrator.actor_scheduler.emit_stage_skipped"
    ) as emit:
        scheduler._mark_skipped(node, reason="condition_never_satisfied")
        emit.assert_called_once_with("waf", "condition_never_satisfied")
