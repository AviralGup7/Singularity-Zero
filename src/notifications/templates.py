"""Title/body templates for console notifications."""

from __future__ import annotations

from src.notifications.events import Notification, NotificationEvent, NotificationPriority


def job_completed(job_id: str, hostname: str, findings: int) -> Notification:
    return Notification(
        title=f"Scan complete · {hostname}",
        message=f"Job {job_id} finished with {findings} findings.",
        event=NotificationEvent.JOB_COMPLETED,
        priority=NotificationPriority.NORMAL if findings else NotificationPriority.LOW,
        entity_id=job_id,
        entity_type="job",
        href=f"/jobs/{job_id}",
        metadata={"findings": findings, "hostname": hostname},
    )


def job_failed(job_id: str, hostname: str, reason: str) -> Notification:
    return Notification(
        title=f"Scan failed · {hostname}",
        message=reason or f"Job {job_id} failed",
        event=NotificationEvent.JOB_FAILED,
        priority=NotificationPriority.HIGH,
        entity_id=job_id,
        entity_type="job",
        href=f"/jobs/{job_id}",
    )


def stage_failed(job_id: str, stage: str, reason: str) -> Notification:
    return Notification(
        title=f"Stage failed · {stage}",
        message=reason,
        event=NotificationEvent.STAGE_FAILED,
        priority=NotificationPriority.HIGH,
        entity_id=job_id,
        entity_type="job",
        href=f"/jobs/{job_id}",
        metadata={"stage": stage},
    )


def self_healing(action: str, tool: str, detail: str) -> Notification:
    return Notification(
        title=f"Self-healing · {tool}",
        message=f"{action}: {detail}",
        event=NotificationEvent.SELF_HEALING,
        priority=NotificationPriority.NORMAL,
        source="self-healing",
        metadata={"action": action, "tool": tool},
    )
