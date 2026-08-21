"""UI-facing projections of domain records.

The FastAPI job schema is larger; these cards are the subset the console
shell actually renders after Demo Sign In.
"""

from __future__ import annotations

import time
from typing import Any

from src.auth.sessions import describe
from src.jobs.query import JobFilter, Page
from src.jobs.summary import summarize
from src.notifications.events import Notification


def job_card(job: dict[str, Any], *, now: float) -> dict[str, Any]:
    summary = summarize(job, now=now)
    return {
        "id": job.get("id"),
        "base_url": job.get("base_url"),
        "hostname": job.get("hostname"),
        "target_name": job.get("target_name"),
        "mode": job.get("mode"),
        "status": summary["status"],
        "stage": summary["stage"],
        "stage_label": job.get("stage_label") or summary["stage"],
        "status_message": job.get("status_message") or "",
        "progress_percent": summary["progress_percent"],
        "elapsed_label": summary["elapsed_label"],
        "eta_label": summary["eta_label"],
        "stalled": summary["stalled"],
        "findings_count": summary["findings_count"],
        "critical_findings": summary["critical_findings"],
        "error": summary["error"],
        "failed_stage": summary["failed_stage"],
        "stop_requested": bool(job.get("stop_requested")),
        "started_at": job.get("started_at"),
        "updated_at": job.get("updated_at"),
        "finished_at": job.get("finished_at"),
        "state_version": job.get("state_version"),
    }


def job_page(page: Page, *, now: float) -> dict[str, Any]:
    return {
        "jobs": [job_card(job, now=now) for job in page.items],
        "total": page.total,
        "offset": page.offset,
        "limit": page.limit,
        "has_more": page.has_more,
    }


def notification_card(item: Notification) -> dict[str, Any]:
    """JWT inbox row shape so the existing React hook can parse console replies."""
    created = float(item.created_at)
    iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(created))
    return {
        "id": item.notification_id,
        "event": item.event.value,
        "priority": item.priority.value,
        "title": item.title,
        "message": item.message,
        "metadata": "{}",
        "source": item.source,
        "correlation_id": None,
        "entity_id": item.entity_id,
        "entity_type": item.entity_type,
        "href": item.href,
        "read": 1 if item.read else 0,
        "created_at": iso,
    }


def session_card(session: Any) -> dict[str, Any]:
    return describe(session)


def filter_from_query(query: dict[str, Any]) -> JobFilter:
    status = query.get("status")
    hostname = query.get("hostname") or query.get("search_host")
    mode = query.get("mode")
    search = query.get("search")
    active = _truthy(query.get("active_only"))
    terminal = _truthy(query.get("terminal_only"))
    min_findings = query.get("min_findings")
    return JobFilter(
        status=str(status) if status else None,
        hostname=str(hostname) if hostname else None,
        mode=str(mode) if mode else None,
        search=str(search) if search else None,
        active_only=active,
        terminal_only=terminal,
        min_findings=int(min_findings) if min_findings not in (None, "") else None,
    )


def _truthy(value: object) -> bool:
    if isinstance(value, bool):
        return value
    raw = str(value or "").strip().lower()
    return raw in {"1", "true", "yes", "on"}
