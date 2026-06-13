"""Unit tests for GRC Control Maturity, SLA Tracking, and Chameleon Evasion lookups."""

from __future__ import annotations

import time

import pytest

from src.execution.frontier.chameleon_evasion import PPOEvasionModel
from src.infrastructure.notifications.base import NotificationPriority
from src.infrastructure.notifications.manager import ManagerConfig, NotificationManager
from src.reporting.compliance_maturity import ControlMaturity, calculate_overall_grc_score
from src.reporting.sla_tracker import SLATracker


def test_calculate_overall_grc_score() -> None:
    # Test cases mapping control ID -> ControlMaturity
    # 1. Neutral / empty
    res_empty = calculate_overall_grc_score({})
    assert res_empty["overall_score"] == 100.0
    assert res_empty["band"] == "PASS"

    # 2. All passing
    maturities = {
        "AC-3": ControlMaturity.PASS,
        "SI-10": ControlMaturity.PASS,
    }
    res_all_pass = calculate_overall_grc_score(maturities)
    assert res_all_pass["overall_score"] == 100.0
    assert res_all_pass["band"] == "PASS"

    # 3. Partial GRC compliance
    maturities_partial = {
        "AC-3": ControlMaturity.PASS,
        "SI-10": ControlMaturity.PARTIAL,
    }
    res_partial = calculate_overall_grc_score(maturities_partial)
    assert res_partial["overall_score"] == 85.0
    assert res_partial["band"] == "PASS"  # overall >= 85 and zero FAIL/AT_RISK

    # 4. Failed control due to critical finding
    maturities_failed = {
        "AC-3": ControlMaturity.PASS,
        "SI-10": ControlMaturity.FAIL,
    }
    res_failed = calculate_overall_grc_score(maturities_failed)
    assert res_failed["overall_score"] == 50.0
    assert res_failed["band"] == "FAIL"


def test_sla_compliance_tracker() -> None:
    now = time.time()

    # 1. Setup sample findings
    findings = [
        {
            "id": "find-1",
            "severity": "critical",
            "title": "Critical RCE",
            "discovered_at": now - (15 * 24 * 60 * 60),  # 15 days ago -> Overdue (SLA: 14 days)
        },
        {
            "id": "find-2",
            "severity": "high",
            "title": "High SQLi",
            "discovered_at": now - (5 * 24 * 60 * 60),  # 5 days ago -> Compliant (SLA: 30 days)
        },
        {
            "id": "find-3",
            "severity": "info",
            "title": "Info Disclosure",
            "discovered_at": now
            - (200 * 24 * 60 * 60),  # 200 days ago -> Compliant (Info has no SLA limits)
        },
    ]

    report = SLATracker.check_sla_compliance(findings, current_time=now)
    assert report["total"] == 3
    assert report["compliant_count"] == 2
    assert report["overdue_count"] == 1
    assert report["overdue"][0]["id"] == "find-1"
    assert report["overdue"][0]["sla_status"] == "BREACHED"
    assert report["compliant"][0]["id"] in {"find-2", "find-3"}


@pytest.mark.anyio
async def test_auto_escalate_overdue_alerts() -> None:
    now = time.time()
    findings = [
        {
            "id": "find-1",
            "severity": "critical",
            "title": "Critical RCE",
            "discovered_at": now - (16 * 24 * 60 * 60),
            "triaged_at": now - (15 * 24 * 60 * 60),
        }
    ]

    config = ManagerConfig()
    notification_manager = NotificationManager(config)
    await notification_manager.initialize()

    # Track emails/slack sends
    sent_events = []

    class MockNotifier:
        def __init__(self):
            self.channel_name = "mock"
            self.config = type("Config", (), {"min_priority": NotificationPriority.LOW})()

        async def send(self, event, priority, title, message, metadata, correlation_id):
            sent_events.append(
                {
                    "event": event,
                    "priority": priority,
                    "title": title,
                    "message": message,
                    "metadata": metadata,
                }
            )
            return type("Result", (), {"success": True, "channel": "mock"})()

        async def close(self):
            pass

    notification_manager.register_notifier("mock", MockNotifier())

    escalations = await SLATracker.auto_escalate_overdue(
        findings, notification_manager, "target.example", current_time=now
    )

    assert escalations == 1
    assert len(sent_events) == 1
    assert "SLA BREACH ALERT" in sent_events[0]["title"]
    assert sent_events[0]["priority"] == NotificationPriority.CRITICAL
    assert sent_events[0]["metadata"]["sla_status"] == "BREACHED"

    await notification_manager.close()


def test_chameleon_hmm_vectorized_transitions() -> None:
    # Instantiate the Hidden Markov Model
    model = PPOEvasionModel()

    # Assert HMM initializes in undetected state
    assert model.get_current_state() == PPOEvasionModel.STATE_UNDETECTED

    # Trigger observation transitions
    model.observe(PPOEvasionModel.OBS_CHALLENGE)
    # Undetected (0) with challenge (1) -> should step state if transition is active
    state1 = model.get_current_state()
    assert state1 in {
        PPOEvasionModel.STATE_UNDETECTED,
        PPOEvasionModel.STATE_SUSPECTED,
        PPOEvasionModel.STATE_BLOCKED,
    }

    # Observe subsequent blocks
    model.observe(PPOEvasionModel.OBS_BLOCK)
    state2 = model.get_current_state()
    assert state2 in {
        PPOEvasionModel.STATE_SUSPECTED,
        PPOEvasionModel.STATE_BLOCKED,
        PPOEvasionModel.STATE_EVADING,
    }
