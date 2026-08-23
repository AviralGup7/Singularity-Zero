"""What to run next given hunt budget and current stage."""

from __future__ import annotations

from dataclasses import dataclass

from src.decision.hunt_budget import HuntBudgetEnforcer
from src.decision.next_action import should_stop
from src.jobs.stages import STAGE_ORDER, StageKey, parse_stage_key


@dataclass(frozen=True, slots=True)
class Plan:
    action: str
    stage: str | None
    reason: str

    def to_dict(self) -> dict[str, object]:
        return {"action": self.action, "stage": self.stage, "reason": self.reason}


def plan_next(
    *,
    current_stage: object,
    enforcer: HuntBudgetEnforcer | None = None,
    failed: bool = False,
    stop_requested: bool = False,
    findings: int = 0,
) -> Plan:
    if stop_requested:
        return Plan(action="stop", stage=None, reason="stop_requested")
    if failed:
        return Plan(
            action="fail", stage=parse_stage_key(current_stage).value, reason="stage_failed"
        )
    if enforcer is not None:
        if should_stop(enforcer):
            return Plan(action="stop", stage=None, reason="budget_exhausted")
        enforcer.record_finding(0.8 if findings else 0.0)
    current = parse_stage_key(current_stage)
    order = list(STAGE_ORDER)
    try:
        index = order.index(current)
    except ValueError:
        index = 0
    if current is StageKey.COMPLETED or index + 1 >= len(order):
        return Plan(action="complete", stage=StageKey.COMPLETED.value, reason="pipeline_complete")
    nxt = order[index + 1]
    return Plan(action="run", stage=nxt.value, reason="advance")


def skip_to_reporting(current_stage: object) -> Plan:
    current = parse_stage_key(current_stage)
    if current in {StageKey.REPORTING, StageKey.COMPLETED}:
        return Plan(action="run", stage=current.value, reason="already_reporting")
    return Plan(action="skip", stage=StageKey.REPORTING.value, reason="fast_path_report")
