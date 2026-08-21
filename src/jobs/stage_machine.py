"""Per-stage finite state machine used by the simulator and store."""

from __future__ import annotations

from src.jobs.stages import StageStatus, parse_stage_status


_ALLOWED: dict[StageStatus, frozenset[StageStatus]] = {
    StageStatus.PENDING: frozenset(
        {StageStatus.RUNNING, StageStatus.SKIPPED, StageStatus.FAILED, StageStatus.PENDING}
    ),
    StageStatus.RUNNING: frozenset(
        {
            StageStatus.RUNNING,
            StageStatus.COMPLETED,
            StageStatus.FAILED,
            StageStatus.RETRYING,
            StageStatus.SKIPPED,
        }
    ),
    StageStatus.RETRYING: frozenset(
        {StageStatus.RUNNING, StageStatus.FAILED, StageStatus.SKIPPED, StageStatus.RETRYING}
    ),
    StageStatus.COMPLETED: frozenset({StageStatus.COMPLETED}),
    StageStatus.FAILED: frozenset({StageStatus.FAILED, StageStatus.RETRYING}),
    StageStatus.SKIPPED: frozenset({StageStatus.SKIPPED}),
}


def can_move_stage(current: object, target: object) -> bool:
    source = parse_stage_status(current)
    dest = parse_stage_status(target)
    return dest in _ALLOWED.get(source, frozenset())


def move_stage(current: object, target: object) -> StageStatus:
    dest = parse_stage_status(target)
    if can_move_stage(current, dest):
        return dest
    return parse_stage_status(current)
