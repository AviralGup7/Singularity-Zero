"""Remediation SLA tracking and automated GRC escalation engine.

Provides automated checks against critical (14-day) and high (30-day) severity SLAs.
"""

from __future__ import annotations

import logging
import time
from typing import Any

from src.infrastructure.notifications.base import NotificationEvent, NotificationPriority
from src.infrastructure.notifications.manager import NotificationManager

logger = logging.getLogger(__name__)


class SLATracker:
    """Manages remediation SLA schedules and auto-escalations for severe findings."""

    SLA_CRITICAL_SECONDS = 14 * 24 * 60 * 60  # 14 days
    SLA_HIGH_SECONDS = 30 * 24 * 60 * 60      # 30 days
    SLA_MEDIUM_SECONDS = 90 * 24 * 60 * 60    # 90 days

    @classmethod
    def check_sla_compliance(
        self,
        findings: list[dict[str, Any]],
        current_time: float | None = None,
    ) -> dict[str, Any]:
        """Verify which findings are within SLA bounds and which are breached/overdue.

        Args:
            findings: List of pipeline finding dictionaries.
            current_time: Reference physical time (defaults to time.time()).

        Returns:
            Dict containing counts, compliant list, and overdue/breached lists.
        """
        ref_time = current_time or time.time()
        overdue_findings = []
        compliant_findings = []

        for finding in findings:
            severity = str(finding.get("severity", "info")).lower()
            if severity not in {"critical", "high", "medium"}:
                # Low/info have no SLA constraints
                compliant_findings.append(finding)
                continue

            # Determine discovery timestamp
            disc_ts = finding.get("discovered_at") or finding.get("timestamp") or ref_time
            if isinstance(disc_ts, str):
                try:
                    # If ISO timestamp string
                    import datetime
                    disc_ts = datetime.datetime.fromisoformat(disc_ts).timestamp()
                except Exception:
                    disc_ts = ref_time

            age = ref_time - float(disc_ts)
            sla_limit = self.SLA_MEDIUM_SECONDS
            if severity == "critical":
                sla_limit = self.SLA_CRITICAL_SECONDS
            elif severity == "high":
                sla_limit = self.SLA_HIGH_SECONDS

            finding_copy = dict(finding)
            finding_copy["sla_limit_seconds"] = sla_limit
            finding_copy["age_seconds"] = age
            finding_copy["days_remaining"] = round((sla_limit - age) / (24 * 60 * 60), 2)

            if age > sla_limit:
                finding_copy["sla_status"] = "BREACHED"
                overdue_findings.append(finding_copy)
            else:
                finding_copy["sla_status"] = "COMPLIANT"
                compliant_findings.append(finding_copy)

        return {
            "total": len(findings),
            "compliant_count": len(compliant_findings),
            "overdue_count": len(overdue_findings),
            "compliant": compliant_findings,
            "overdue": overdue_findings,
        }

    @classmethod
    async def auto_escalate_overdue(
        self,
        findings: list[dict[str, Any]],
        notification_manager: NotificationManager,
        target_name: str,
        current_time: float | None = None,
    ) -> int:
        """Scan findings for SLA breaches and auto-escalate overdue items via notifications.

        Args:
            findings: List of finding dictionaries.
            notification_manager: Configured NotificationManager instance.
            target_name: Target being analyzed.
            current_time: Physical clock reference.

        Returns:
            Count of escalated alerts fired.
        """
        sla_report = self.check_sla_compliance(findings, current_time)
        escalated_count = 0

        for f in sla_report["overdue"]:
            fid = f.get("id") or f.get("finding_id") or "unknown"
            severity = f.get("severity", "medium").upper()
            title = f.get("title") or f.get("description") or "Security finding"
            days_overdue = abs(round(f["days_remaining"], 1))

            alert_title = f"SLA BREACH ALERT: Overdue {severity} Vulnerability on {target_name}"
            alert_message = (
                f"Vulnerability '{title}' (ID: {fid}) has breached its remediation SLA by {days_overdue} days.\n"
                f"SLA threshold: {round(f['sla_limit_seconds'] / (24*60*60))} days. "
                f"Current age: {round(f['age_seconds'] / (24*60*60))} days.\n"
                f"Immediate action is required to remediate this finding."
            )

            priority = NotificationPriority.CRITICAL if severity == "CRITICAL" else NotificationPriority.HIGH
            
            # Send notification
            await notification_manager.send(
                event=NotificationEvent.COMPLIANCE_VIOLATION,
                priority=priority,
                title=alert_title,
                message=alert_message,
                metadata={
                    "finding_id": fid,
                    "target": target_name,
                    "severity": severity,
                    "days_overdue": days_overdue,
                    "sla_status": "BREACHED"
                },
                correlation_id=fid
            )
            escalated_count += 1

        return escalated_count
