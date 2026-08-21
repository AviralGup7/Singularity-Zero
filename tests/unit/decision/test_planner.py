from __future__ import annotations

from src.decision.planner import plan_next, skip_to_reporting
from src.decision.scoring import finding_priority, order_findings, top_n
from src.jobs.stages import StageKey


def test_plan_advances_and_stops() -> None:
    nxt = plan_next(current_stage="startup")
    assert nxt.action == "run"
    assert nxt.stage == StageKey.SUBDOMAINS.value
    stopped = plan_next(current_stage="active_scan", stop_requested=True)
    assert stopped.action == "stop"
    assert skip_to_reporting("active_scan").stage == StageKey.REPORTING.value


def test_finding_priority_orders_admin_urls() -> None:
    findings = [
        {"title": "a", "severity": "low", "confidence": 0.9, "url": "/health"},
        {"title": "b", "severity": "medium", "confidence": 0.5, "url": "/admin/users"},
    ]
    ordered = order_findings(findings)
    assert ordered[0]["title"] == "b"
    assert finding_priority(ordered[0]) >= finding_priority(ordered[1])
    assert len(top_n(findings, 1)) == 1
