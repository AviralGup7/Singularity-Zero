"""Notification event model."""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class NotificationPriority(StrEnum):
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    CRITICAL = "critical"


class NotificationEvent(StrEnum):
    JOB_COMPLETED = "job.completed"
    JOB_FAILED = "job.failed"
    NEW_FINDING = "finding.new"
    CRITICAL_FINDING = "finding.critical"
    STAGE_FAILED = "job.stage_failed"
    SELF_HEALING = "self_healing"
    SYSTEM = "system"
    AUTH = "auth"


@dataclass(slots=True)
class Notification:
    title: str
    message: str
    event: NotificationEvent = NotificationEvent.SYSTEM
    priority: NotificationPriority = NotificationPriority.NORMAL
    source: str = "console"
    read: bool = False
    href: str | None = None
    entity_id: str | None = None
    entity_type: str | None = None
    notification_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    created_at: float = field(default_factory=time.time)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.notification_id,
            "title": self.title,
            "message": self.message,
            "event": self.event.value,
            "priority": self.priority.value,
            "source": self.source,
            "read": self.read,
            "href": self.href,
            "entity_id": self.entity_id,
            "entity_type": self.entity_type,
            "created_at": self.created_at,
            "metadata": dict(self.metadata),
        }

    def mark_read(self) -> Notification:
        self.read = True
        return self


def from_job_status(job_id: str, status: str, *, message: str = "") -> Notification | None:
    if status == "completed":
        return Notification(
            title="Job completed",
            message=message or f"Job {job_id} finished",
            event=NotificationEvent.JOB_COMPLETED,
            priority=NotificationPriority.NORMAL,
            entity_id=job_id,
            entity_type="job",
            href=f"/jobs/{job_id}",
        )
    if status == "failed":
        return Notification(
            title="Job failed",
            message=message or f"Job {job_id} failed",
            event=NotificationEvent.JOB_FAILED,
            priority=NotificationPriority.HIGH,
            entity_id=job_id,
            entity_type="job",
            href=f"/jobs/{job_id}",
        )
    return None


def from_finding(*, finding_id: str, title: str, severity: str) -> Notification:
    critical = severity.lower() in {"critical", "high"}
    return Notification(
        title=title,
        message=f"{severity} finding {finding_id}",
        event=NotificationEvent.CRITICAL_FINDING if critical else NotificationEvent.NEW_FINDING,
        priority=NotificationPriority.CRITICAL if severity.lower() == "critical" else NotificationPriority.HIGH,
        entity_id=finding_id,
        entity_type="finding",
        href=f"/findings/{finding_id}",
        metadata={"severity": severity},
    )
