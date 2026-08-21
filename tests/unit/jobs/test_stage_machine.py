from __future__ import annotations

from src.jobs.stage_machine import can_move_stage, move_stage
from src.jobs.stages import StageStatus


def test_running_can_complete() -> None:
    assert can_move_stage(StageStatus.RUNNING, StageStatus.COMPLETED)
    assert move_stage("running", "completed") is StageStatus.COMPLETED


def test_completed_is_terminal() -> None:
    assert not can_move_stage(StageStatus.COMPLETED, StageStatus.RUNNING)
    assert move_stage("completed", "running") is StageStatus.COMPLETED
