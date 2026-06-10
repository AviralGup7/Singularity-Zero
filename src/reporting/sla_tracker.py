"""Remediation SLA tracking and automated GRC escalation engine.

Provides automated checks against critical (14-day) and high (30-day) severity SLAs.

The tracker now exposes per-stage lifecycle metrics in addition
to the legacy "days since discovery" check:

* ``triage_lag_days`` - time from discovery to analyst triage.
* ``remediation_days`` - time spent in the IN_REMEDIATION state.
* ``verification_days`` - time from FIXED to VERIFIED.

It also produces a ``lifecycle_summary`` so GRC dashboards can
spot process bottlenecks (e.g. "all criticals are stuck in
TRIAGED for 11 days").
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
    SLA_HIGH_SECONDS = 30 * 24 * 60 * 60  # 30 days
    SLA_MEDIUM_SECONDS = 90 * 24 * 60 * 60  # 90 days

    # Per-stage SLA targets in days. Triage and verification have
    # short fixed targets; remediation mirrors the legacy
    # severity-based table.
    TRIAGE_SLA_DAYS = 2.0
    VERIFICATION_SLA_DAYS = 5.0

    @classmethod
    def check_sla_compliance(
        cls,
        findings: list[dict[str, Any]],
        current_time: float | None = None,
    ) -> dict[str, Any]:
        """Verify which findings are within SLA bounds and which are breached/overdue.

        Args:
            findings: List of pipeline finding dictionaries.
            current_time: Reference physical time (defaults to time.time()).

        Returns:
            Dict containing counts, compliant list, overdue/breached lists,
            and per-stage lifecycle metrics.
        """
        ref_time = current_time or time.time()
        overdue_findings = []
        compliant_findings = []

        for finding in findings:
            severity = str(finding.get("severity", "info")).lower()
            finding_copy = dict(finding)

            # Per-stage lifecycle metrics are computed when the
            # finding carries the relevant timestamp fields.
            lifecycle_metrics = _compute_lifecycle_metrics(finding, ref_time)
            finding_copy.update(lifecycle_metrics)

            if severity not in {"critical", "high", "medium"}:
                # Low/info have no SLA constraints
                finding_copy["sla_status"] = "N/A"
                compliant_findings.append(finding_copy)
                continue

            disc_ts = (
                finding.get("timestamp")
                or finding.get("discovered_at")
                or finding.get("created_at")
                or finding.get("detected_at")
                or ref_time
            )
            if isinstance(disc_ts, str):
                try:
                    import datetime

                    disc_ts = datetime.datetime.fromisoformat(
                        disc_ts.replace("Z", "+00:00")
                    ).timestamp()
                except (ValueError, TypeError) as exc:
                    logger.warning("Malformed SLA timestamp %r: %s", disc_ts, exc)
                    disc_ts = ref_time

            age = ref_time - float(disc_ts)
            sla_limit = cls.SLA_MEDIUM_SECONDS
            if severity == "critical":
                sla_limit = cls.SLA_CRITICAL_SECONDS
            elif severity == "high":
                sla_limit = cls.SLA_HIGH_SECONDS

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
            "triage_sla_days": cls.TRIAGE_SLA_DAYS,
            "verification_sla_days": cls.VERIFICATION_SLA_DAYS,
        }

    @classmethod
    def lifecycle_summary(
        cls,
        findings: list[dict[str, Any]],
        current_time: float | None = None,
    ) -> dict[str, Any]:
        """Aggregate per-stage lag metrics across a set of findings.

        Returns a dict with average and worst-case ``triage_lag_days``,
        ``remediation_days``, ``verification_days`` plus a list of
        findings that have breached a per-stage SLA. Useful for GRC
        dashboards that want to show "triage SLA compliance" and
        "verification SLA compliance" as separate KPIs from the
        legacy "remediation within N days" metric.
        """
        ref_time = current_time or time.time()
        triage_total = 0.0
        triage_count = 0
        triage_breach_count = 0
        verification_total = 0.0
        verification_count = 0
        verification_breach_count = 0
        by_state: dict[str, int] = {}
        breaches: list[dict[str, Any]] = []
        worst_triage_lag = 0.0
        worst_remediation_days = 0.0

        for finding in findings:
            state = str(finding.get("lifecycle_state", "OPEN")).upper()
            by_state[state] = by_state.get(state, 0) + 1

            metrics = _compute_lifecycle_metrics(finding, ref_time)
            triage_lag = metrics.get("triage_lag_days")
            if isinstance(triage_lag, (int, float)):
                triage_total += triage_lag
                triage_count += 1
                worst_triage_lag = max(worst_triage_lag, triage_lag)
                if state in {"OPEN", "REOPENED"} and triage_lag > cls.TRIAGE_SLA_DAYS:
                    triage_breach_count += 1
                    breaches.append(
                        {
                            "finding_id": finding.get("id") or finding.get("finding_id"),
                            "stage": "triage",
                            "lag_days": round(triage_lag, 2),
                            "target_days": cls.TRIAGE_SLA_DAYS,
                            "state": state,
                        }
                    )

            remediation_days = metrics.get("remediation_days")
            if isinstance(remediation_days, (int, float)):
                worst_remediation_days = max(worst_remediation_days, remediation_days)

            verification_days = metrics.get("verification_days")
            if isinstance(verification_days, (int, float)):
                verification_total += verification_days
                verification_count += 1
                if state == "FIXED" and verification_days > cls.VERIFICATION_SLA_DAYS:
                    verification_breach_count += 1
                    breaches.append(
                        {
                            "finding_id": finding.get("id") or finding.get("finding_id"),
                            "stage": "verification",
                            "lag_days": round(verification_days, 2),
                            "target_days": cls.VERIFICATION_SLA_DAYS,
                            "state": state,
                        }
                    )

        return {
            "total": len(findings),
            "by_state": by_state,
            "avg_triage_lag_days": round(triage_total / triage_count, 2) if triage_count else 0.0,
            "avg_verification_days": round(verification_total / verification_count, 2)
            if verification_count
            else 0.0,
            "worst_triage_lag_days": round(worst_triage_lag, 2),
            "worst_remediation_days": round(worst_remediation_days, 2),
            "triage_breach_count": triage_breach_count,
            "verification_breach_count": verification_breach_count,
            "triage_sla_days": cls.TRIAGE_SLA_DAYS,
            "verification_sla_days": cls.VERIFICATION_SLA_DAYS,
            "breaches": breaches,
        }

    @classmethod
    async def auto_escalate_overdue(
        cls,
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
        sla_report = cls.check_sla_compliance(findings, current_time)
        escalated_count = 0

        for f in sla_report["overdue"]:
            fid = f.get("id") or f.get("finding_id") or "unknown"
            severity = f.get("severity", "medium").upper()
            title = f.get("title") or f.get("description") or "Security finding"
            days_overdue = abs(round(f["days_remaining"], 1))

            alert_title = f"SLA BREACH ALERT: Overdue {severity} Vulnerability on {target_name}"
            alert_message = (
                f"Vulnerability '{title}' (ID: {fid}) has breached its remediation SLA by {days_overdue} days.\n"
                f"SLA threshold: {round(f['sla_limit_seconds'] / (24 * 60 * 60))} days. "
                f"Current age: {round(f['age_seconds'] / (24 * 60 * 60))} days.\n"
                f"Immediate action is required to remediate this finding."
            )

            priority = (
                NotificationPriority.CRITICAL
                if severity == "CRITICAL"
                else NotificationPriority.HIGH
            )

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
                    "sla_status": "BREACHED",
                },
                correlation_id=fid,
            )
            escalated_count += 1

        # Also escalate per-stage SLA breaches (triage lag,
        # verification lag). These get a different notification
        # event so consumers can route them differently.
        lifecycle = cls.lifecycle_summary(findings, current_time)
        for breach in lifecycle.get("breaches", []):
            stage = str(breach.get("stage", "")).upper()
            fid = breach.get("finding_id") or "unknown"
            lag = breach.get("lag_days", 0)
            target = breach.get("target_days", 0)
            priority = (
                NotificationPriority.HIGH if stage == "TRIAGE" else NotificationPriority.MEDIUM
            )
            await notification_manager.send(
                event=NotificationEvent.COMPLIANCE_VIOLATION,
                priority=priority,
                title=(f"SLA STAGE BREACH: {stage} lag {round(float(lag), 1)}d on {target_name}"),
                message=(
                    f"Finding {fid} breached its {stage.lower()} SLA: "
                    f"{round(float(lag), 1)} days (target {target})."
                ),
                metadata={
                    "finding_id": fid,
                    "target": target_name,
                    "stage": stage.lower(),
                    "lag_days": lag,
                    "target_days": target,
                },
                correlation_id=fid,
            )
            escalated_count += 1

        if escalated_count > 0:
            logger.info(
                "GRC Auto-Escalation: Fired %d SLA breach notifications for target %s.",
                escalated_count,
                target_name,
            )

        return escalated_count


def _compute_lifecycle_metrics(finding: dict[str, Any], ref_time: float) -> dict[str, Any]:
    """Return per-stage lag metrics for a finding."""
    metrics: dict[str, Any] = {
        "triage_lag_days": None,
        "remediation_days": None,
        "verification_days": None,
    }
    discovered_at = _coerce_ts(
        finding.get("timestamp")
        or finding.get("discovered_at")
        or finding.get("created_at")
        or finding.get("detected_at")
    )
    triaged_at = _coerce_ts(finding.get("triaged_at"))
    remediation_started_at = _coerce_ts(finding.get("remediation_started_at"))
    fixed_at = _coerce_ts(finding.get("fixed_at"))
    verified_at = _coerce_ts(finding.get("verified_at"))

    if discovered_at is not None and triaged_at is not None:
        metrics["triage_lag_days"] = round(max(0.0, (triaged_at - discovered_at) / 86400.0), 3)
    elif discovered_at is not None and triaged_at is None:
        # Triage is in-flight - report the time spent waiting.
        metrics["triage_lag_days"] = round(max(0.0, (ref_time - discovered_at) / 86400.0), 3)
    if remediation_started_at is not None and fixed_at is not None:
        metrics["remediation_days"] = round(
            max(0.0, (fixed_at - remediation_started_at) / 86400.0), 3
        )
    elif remediation_started_at is not None and fixed_at is None:
        metrics["remediation_days"] = round(
            max(0.0, (ref_time - remediation_started_at) / 86400.0), 3
        )
    if fixed_at is not None and verified_at is not None:
        metrics["verification_days"] = round(max(0.0, (verified_at - fixed_at) / 86400.0), 3)
    elif fixed_at is not None and verified_at is None:
        metrics["verification_days"] = round(max(0.0, (ref_time - fixed_at) / 86400.0), 3)
    return metrics


def _coerce_ts(value: Any) -> float | None:
    if value is None or value is False or value == "":
        return None
    if isinstance(value, (int, float)):
        return float(value)
    try:
        import datetime

        return datetime.datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()
    except (TypeError, ValueError):
        return None
