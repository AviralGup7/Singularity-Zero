"""Unit tests for the Notifications Infrastructure module."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pydantic import HttpUrl

from src.core.contracts.health import CorrectiveAction, HealthComponent
from src.infrastructure.notifications.base import (
    BaseNotifier,
    NotificationConfig,
    NotificationEvent,
    NotificationPayload,
    NotificationPriority,
    NotificationResult,
)
from src.infrastructure.notifications.manager import (
    AlertRoutingPolicy,
    ChannelEntry,
    ManagerConfig,
    NotificationManager,
    get_channel,
    register_channel,
)
from src.infrastructure.notifications.slack import SlackConfig, SlackNotifier
from src.pipeline.self_healing import CorrectionEvent, HealthFinding, HealthStatus


class MockNotifier(BaseNotifier):
    """A mock notifier to test the manager's routing and dispatching logic."""

    def __init__(self, config: NotificationConfig, channel_name: str = "mock_channel") -> None:
        super().__init__(config, channel_name)
        self.sent_payloads: list[NotificationPayload] = []
        self.should_fail = False

    async def _do_send(self, payload: NotificationPayload) -> NotificationResult:
        if self.should_fail:
            raise RuntimeError("Mock send failure")
        self.sent_payloads.append(payload)
        return NotificationResult(
            success=True,
            channel=self._channel_name,
            event=payload.event.value,
            priority=payload.priority.value,
            response_data={"mock": "success"},
        )

    async def close(self) -> None:
        pass


# ===========================================================================
# 1. Registry & Configuration Tests
# ===========================================================================


def test_notifier_registry() -> None:
    """Verify that custom notifiers can be registered and retrieved from the registry."""
    register_channel("mock_notifier_test", MockNotifier)
    retrieved = get_channel("mock_notifier_test")
    assert retrieved is MockNotifier

    # Clean up the registry to keep it clean
    from src.infrastructure.notifications.manager import _CHANNEL_REGISTRY

    _CHANNEL_REGISTRY.pop("mock_notifier_test", None)


def test_alert_routing_policy_rules() -> None:
    """Verify that AlertRoutingPolicy maps self-healing events to standard notification priorities."""
    policy = AlertRoutingPolicy(
        alert_on_successful_recovery=True,
        alert_on_failed_recovery=True,
        alert_on_critical_findings=True,
    )

    finding_critical = HealthFinding(
        component=HealthComponent.QUEUE,
        status=HealthStatus.CRITICAL,
        reason="Disk critical",
        action=CorrectiveAction.RESTART_WORKER,
        metric="disk_space",
    )
    finding_warning = HealthFinding(
        component=HealthComponent.QUEUE,
        status=HealthStatus.DEGRADED,
        reason="Disk warning",
        action=CorrectiveAction.NOOP,
        metric="disk_space",
    )

    # Critical finding alert
    assert policy.priority_for(finding_critical) == NotificationPriority.HIGH
    # Warning finding does not match critical filter
    assert policy.priority_for(finding_warning) is None

    # Failed recovery alert
    failed_correction = CorrectionEvent(
        finding_id=finding_critical.finding_id,
        action=CorrectiveAction.RESTART_WORKER,
        success=False,
        message="Failed database restart",
        component=HealthComponent.QUEUE,
        details={"error": "Process timed out"},
    )
    assert policy.priority_for(finding_critical, failed_correction) == NotificationPriority.CRITICAL

    # Successful recovery alert
    success_correction = CorrectionEvent(
        finding_id=finding_critical.finding_id,
        action=CorrectiveAction.RESTART_WORKER,
        success=True,
        message="Successfully restarted database",
        component=HealthComponent.QUEUE,
        details={},
    )
    assert policy.priority_for(finding_critical, success_correction) == NotificationPriority.MEDIUM


# ===========================================================================
# 2. Notification Manager Unit Tests
# ===========================================================================


@pytest.mark.asyncio
async def test_notification_manager_routing() -> None:
    """Verify that NotificationManager builds, filters, and dispatches to registered channels correctly."""
    config = ManagerConfig(
        channels=[
            ChannelEntry(
                name="mock1",
                config={"timeout_seconds": 5},
                min_priority=NotificationPriority.MEDIUM,
            ),
            ChannelEntry(
                name="mock2",
                config={"timeout_seconds": 10},
                events=[NotificationEvent.CRITICAL_VULNERABILITY],
            ),
        ],
        fail_fast=False,
    )

    register_channel("mock1", MockNotifier)
    register_channel("mock2", MockNotifier)

    try:
        async with NotificationManager(config) as manager:
            # Check channels are populated correctly
            assert "mock1" in manager.channels
            assert "mock2" in manager.channels

            notifier1 = manager.get_channel("mock1")
            notifier2 = manager.get_channel("mock2")
            assert isinstance(notifier1, MockNotifier)
            assert isinstance(notifier2, MockNotifier)

            # Test 1: Send LOW priority event to both.
            # mock1 rejects because priority < MEDIUM.
            # mock2 rejects because event != CRITICAL_VULNERABILITY.
            results1 = await manager.send(
                event=NotificationEvent.SCAN_STARTED,
                priority=NotificationPriority.LOW,
                title="Low priority scan start",
                message="Scanning target",
            )
            assert len(results1) == 0
            assert len(notifier1.sent_payloads) == 0
            assert len(notifier2.sent_payloads) == 0

            # Test 2: Send HIGH priority event (FINDING_DETECTED).
            # mock1 accepts because priority HIGH >= MEDIUM.
            # mock2 rejects because event != CRITICAL_VULNERABILITY.
            results2 = await manager.send(
                event=NotificationEvent.FINDING_DETECTED,
                priority=NotificationPriority.HIGH,
                title="High priority finding",
                message="XSS detected",
            )
            assert len(results2) == 1
            assert results2[0].success is True
            assert results2[0].channel == "mock1"
            assert len(notifier1.sent_payloads) == 1
            assert len(notifier2.sent_payloads) == 0

            # Test 3: Send CRITICAL_VULNERABILITY event (CRITICAL).
            # mock1 accepts because priority CRITICAL >= MEDIUM.
            # mock2 accepts because event is CRITICAL_VULNERABILITY.
            results3 = await manager.send(
                event=NotificationEvent.CRITICAL_VULNERABILITY,
                priority=NotificationPriority.CRITICAL,
                title="Critical CVE found",
                message="RCE CVE-2026-XXXX",
            )
            assert len(results3) == 2
            assert all(r.success for r in results3)
            assert len(notifier1.sent_payloads) == 2
            assert len(notifier2.sent_payloads) == 1

    finally:
        from src.infrastructure.notifications.manager import _CHANNEL_REGISTRY

        _CHANNEL_REGISTRY.pop("mock1", None)
        _CHANNEL_REGISTRY.pop("mock2", None)


@pytest.mark.asyncio
async def test_notification_manager_deduplication() -> None:
    """Verify that NotificationManager deduplicates duplicate alerts within the sliding window."""
    config = ManagerConfig(
        channels=[
            ChannelEntry(name="mock_dedup", config={}),
        ],
        deduplication_window_seconds=1.0,
    )

    register_channel("mock_dedup", MockNotifier)

    try:
        manager = NotificationManager(config)
        await manager.initialize()
        notifier = manager.get_channel("mock_dedup")
        assert isinstance(notifier, MockNotifier)

        # 1. Send first alert
        res1 = await manager.send(
            event=NotificationEvent.SYSTEM_ERROR,
            priority=NotificationPriority.HIGH,
            title="Database Connection Lost",
            message="Lost connection to PostgreSQL server.",
            correlation_id="db-error-1",
        )
        assert len(res1) == 1
        assert len(notifier.sent_payloads) == 1

        # 2. Immediately send duplicate alert (should be suppressed)
        res2 = await manager.send(
            event=NotificationEvent.SYSTEM_ERROR,
            priority=NotificationPriority.HIGH,
            title="Database Connection Lost",
            message="Lost connection to PostgreSQL server.",
            correlation_id="db-error-1",
        )
        assert len(res2) == 0
        assert len(notifier.sent_payloads) == 1

        # 3. Wait for deduplication window to expire
        await asyncio.sleep(1.1)

        # 4. Send alert again (should pass through now)
        res3 = await manager.send(
            event=NotificationEvent.SYSTEM_ERROR,
            priority=NotificationPriority.HIGH,
            title="Database Connection Lost",
            message="Lost connection to PostgreSQL server.",
            correlation_id="db-error-1",
        )
        assert len(res3) == 1
        assert len(notifier.sent_payloads) == 2

        await manager.close()
    finally:
        from src.infrastructure.notifications.manager import _CHANNEL_REGISTRY

        _CHANNEL_REGISTRY.pop("mock_dedup", None)


@pytest.mark.asyncio
async def test_notification_manager_helpers() -> None:
    """Verify standard helper methods inside NotificationManager dispatch clean event payloads."""
    config = ManagerConfig(
        channels=[ChannelEntry(name="mock_helpers", config={})],
    )
    register_channel("mock_helpers", MockNotifier)

    try:
        async with NotificationManager(config) as manager:
            notifier = manager.get_channel("mock_helpers")
            assert isinstance(notifier, MockNotifier)

            # Test send_finding
            await manager.send_finding(
                finding_title="SQL Injection",
                finding_description="Potential SQLi at /users/profile",
                severity="high",
                target="example.com",
                endpoint="/users/profile",
            )
            assert len(notifier.sent_payloads) == 1
            payload = notifier.sent_payloads[-1]
            assert payload.title == "SQL Injection"
            assert payload.priority == NotificationPriority.HIGH
            assert payload.metadata == {
                "severity": "high",
                "target": "example.com",
                "endpoint": "/users/profile",
            }

            # Test send_scan_status
            await manager.send_scan_status(
                status="completed",
                target="api.example.com",
                details={"findings_count": 8},
            )
            assert len(notifier.sent_payloads) == 2
            payload = notifier.sent_payloads[-1]
            assert payload.event == NotificationEvent.SCAN_COMPLETED
            assert payload.priority == NotificationPriority.LOW
            assert payload.metadata == {
                "target": "api.example.com",
                "status": "completed",
                "findings_count": 8,
            }

            # Test send_error
            await manager.send_error(
                error_title="Telemetry Leak",
                error_message="Telemetry stream exposed public keys",
            )
            assert len(notifier.sent_payloads) == 3
            payload = notifier.sent_payloads[-1]
            assert payload.event == NotificationEvent.SYSTEM_ERROR
            assert payload.priority == NotificationPriority.HIGH

            # Test send_compliance_alert
            await manager.send_compliance_alert(
                framework="NIST-SP-800-53",
                control_id="AC-2",
                maturity="FAIL",
                recommendation="Enforce API session rotation",
                target="admin.target.com",
            )
            assert len(notifier.sent_payloads) == 4
            payload = notifier.sent_payloads[-1]
            assert payload.event == NotificationEvent.COMPLIANCE_VIOLATION
            assert payload.priority == NotificationPriority.CRITICAL
            assert payload.metadata == {
                "framework": "NIST-SP-800-53",
                "control_id": "AC-2",
                "maturity": "FAIL",
                "target": "admin.target.com",
            }
    finally:
        from src.infrastructure.notifications.manager import _CHANNEL_REGISTRY

        _CHANNEL_REGISTRY.pop("mock_helpers", None)


# ===========================================================================
# 3. Channel Notifier Implementation Tests
# ===========================================================================


@pytest.mark.asyncio
async def test_slack_notifier_integration() -> None:
    """Verify SlackNotifier formats JSON payloads correctly and dispatches via HTTPX."""
    config = SlackConfig(
        webhook_url=HttpUrl("https://hooks.slack.com/services/T00/B00/X00"),
        channel="#security-alerts",
        username="Test Bot",
        mention_on_critical=["admin-1"],
        timeout_seconds=5.0,
    )

    payload = NotificationPayload(
        event=NotificationEvent.CRITICAL_VULNERABILITY,
        priority=NotificationPriority.CRITICAL,
        title="SQL Injection Found",
        message="Critical injection path fuzzed successfully.",
        metadata={"target": "vuln.com"},
        source="scanner",
        timestamp=datetime.now(UTC),
        correlation_id="job-42",
    )

    # Mock the HTTPX post call to return 200 OK
    mock_response = MagicMock()
    mock_response.status_code = 200

    with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = mock_response

        notifier = SlackNotifier(config)
        result = await notifier._do_send(payload)

        assert result.success is True
        assert result.channel == "slack"

        # Verify the outgoing JSON payload
        mock_post.assert_called_once()
        args, kwargs = mock_post.call_args
        target_url = args[0]
        json_body = kwargs["json"]

        assert target_url == "https://hooks.slack.com/services/T00/B00/X00"
        assert json_body["username"] == "Test Bot"
        assert json_body["channel"] == "#security-alerts"
        # Mention should be present in the fallback text for critical priority
        assert "<@admin-1>" in json_body["text"]

        # Check block layout structure
        blocks = json_body["blocks"]
        assert len(blocks) > 0
        assert blocks[0]["type"] == "header"
        assert "🔴 CRITICAL SQL Injection Found" in blocks[0]["text"]["text"]

        await notifier.close()
