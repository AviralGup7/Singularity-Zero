"""GRC Compliance Notification Alerts Dispatcher.

Filters scan outcomes, evaluates compliance maturity scorebands,
and issues high-priority slack/email updates upon control failures.
"""

from __future__ import annotations

import logging
from typing import Any

from src.infrastructure.notifications.manager import NotificationManager

logger = logging.getLogger(__name__)


class ComplianceAlertsDispatcher:
    """Dispatches alerts when critical or high controls drop to FAIL or AT_RISK."""

    def __init__(self, manager: NotificationManager) -> None:
        self.manager = manager

    def dispatch_maturity_alerts(self, target_name: str, maturity_report: dict[str, Any]) -> None:
        """Analyze control bands and broadcast failure notifications."""
        failed_controls = []
        at_risk_controls = []

        for control_id, data in maturity_report.items():
            if not isinstance(data, dict):
                continue
            status = data.get("status", "PASS").upper()
            description = data.get("description", "Unknown Control")

            if status == "FAIL":
                failed_controls.append(f"{control_id} ({description})")
            elif status == "AT_RISK":
                at_risk_controls.append(f"{control_id} ({description})")

        if not failed_controls and not at_risk_controls:
            logger.info("Compliance control maturity is excellent. Zero failure alerts issued.")
            return

        # Build high-impact GRC alert message
        subject = f"🔴 GRC Compliance Failure Alert - Target: {target_name}"
        body_lines = [
            f"Compliance status check concluded for target: {target_name}",
            "\nThe following operational security controls have failed validation:",
        ]

        for control in failed_controls:
            body_lines.append(f"  - [FAIL] {control}")
        for control in at_risk_controls:
            body_lines.append(f"  - [AT_RISK] {control}")

        body_lines.append(
            "\nImmediate remediation action is required to restore control maturity bands."
        )
        full_msg = "\n".join(body_lines)

        try:
            # Broadcast to all registered channels
            import asyncio

            from src.infrastructure.notifications.base import (
                NotificationEvent,
                NotificationPriority,
            )

            coro = self.manager.send(
                event=NotificationEvent.COMPLIANCE_VIOLATION,
                priority=NotificationPriority.CRITICAL,
                title=subject,
                message=full_msg,
            )
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    loop.create_task(coro)
                else:
                    loop.run_until_complete(coro)
            except RuntimeError:
                asyncio.run(coro)
            logger.info("GRC compliance maturity failure notifications successfully dispatched.")
        except Exception as exc:
            logger.error("Failed to broadcast compliance alerts: %s", exc)
