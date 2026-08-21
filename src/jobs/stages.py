"""Canonical pipeline stage order and labels.

Copied out of the dashboard registry so job domain code does not import
FastAPI or launcher types.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class StageKey(StrEnum):
    STARTUP = "startup"
    SUBDOMAINS = "subdomains"
    LIVE_HOSTS = "live_hosts"
    URLS = "urls"
    PARAMETERS = "parameters"
    RANKING = "ranking"
    PRIORITY = "priority"
    PASSIVE_SCAN = "passive_scan"
    ACTIVE_SCAN = "active_scan"
    NUCLEI = "nuclei"
    ACCESS_CONTROL = "access_control"
    VALIDATION = "validation"
    INTELLIGENCE = "intelligence"
    REPORTING = "reporting"
    COMPLETED = "completed"


STAGE_ORDER: tuple[StageKey, ...] = tuple(StageKey)

STAGE_LABELS: dict[str, str] = {
    StageKey.STARTUP.value: "Startup",
    StageKey.SUBDOMAINS.value: "Subdomains",
    StageKey.LIVE_HOSTS.value: "Live hosts",
    StageKey.URLS.value: "URLs",
    StageKey.PARAMETERS.value: "Parameters",
    StageKey.RANKING.value: "Ranking",
    StageKey.PRIORITY.value: "Priority",
    StageKey.PASSIVE_SCAN.value: "Passive scan",
    StageKey.ACTIVE_SCAN.value: "Active scan",
    StageKey.NUCLEI.value: "Nuclei",
    StageKey.ACCESS_CONTROL.value: "Access control",
    StageKey.VALIDATION.value: "Validation",
    StageKey.INTELLIGENCE.value: "Intelligence",
    StageKey.REPORTING.value: "Reporting",
    StageKey.COMPLETED.value: "Completed",
}

STAGE_PERCENT_BANDS: dict[str, tuple[int, int]] = {
    StageKey.STARTUP.value: (0, 4),
    StageKey.SUBDOMAINS.value: (4, 12),
    StageKey.LIVE_HOSTS.value: (12, 20),
    StageKey.URLS.value: (20, 32),
    StageKey.PARAMETERS.value: (32, 40),
    StageKey.RANKING.value: (40, 46),
    StageKey.PRIORITY.value: (46, 50),
    StageKey.PASSIVE_SCAN.value: (50, 62),
    StageKey.ACTIVE_SCAN.value: (62, 78),
    StageKey.NUCLEI.value: (78, 84),
    StageKey.ACCESS_CONTROL.value: (84, 88),
    StageKey.VALIDATION.value: (88, 92),
    StageKey.INTELLIGENCE.value: (92, 96),
    StageKey.REPORTING.value: (96, 99),
    StageKey.COMPLETED.value: (99, 100),
}


class StageStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    RETRYING = "retrying"


@dataclass(frozen=True, slots=True)
class StageProgress:
    stage: str
    status: StageStatus
    processed: int = 0
    total: int | None = None
    percent: int = 0
    reason: str = ""
    error: str = ""
    retry_count: int = 0
    last_event: str = ""
    started_at: float | None = None
    updated_at: float | None = None

    @property
    def label(self) -> str:
        return STAGE_LABELS.get(self.stage, self.stage.replace("_", " ").title())

    def to_dict(self) -> dict[str, object]:
        return {
            "stage": self.stage,
            "stage_label": self.label,
            "status": self.status.value,
            "processed": self.processed,
            "total": self.total,
            "percent": self.percent,
            "reason": self.reason,
            "error": self.error,
            "retry_count": self.retry_count,
            "last_event": self.last_event,
            "started_at": self.started_at,
            "updated_at": self.updated_at,
        }


def parse_stage_key(value: object) -> StageKey:
    raw = str(value or "").strip().lower()
    for key in StageKey:
        if raw == key.value:
            return key
    aliases = {
        "recon": StageKey.SUBDOMAINS,
        "hosts": StageKey.LIVE_HOSTS,
        "passive": StageKey.PASSIVE_SCAN,
        "active": StageKey.ACTIVE_SCAN,
        "enrichment": StageKey.INTELLIGENCE,
        "report": StageKey.REPORTING,
        "done": StageKey.COMPLETED,
    }
    return aliases.get(raw, StageKey.STARTUP)


def parse_stage_status(value: object) -> StageStatus:
    raw = str(value or "").strip().lower()
    for status in StageStatus:
        if raw == status.value:
            return status
    if raw in {"ok", "success", "done"}:
        return StageStatus.COMPLETED
    if raw in {"error", "crashed"}:
        return StageStatus.FAILED
    if raw in {"skip", "skipped_deadline"}:
        return StageStatus.SKIPPED
    if raw in {"busy", "in_progress"}:
        return StageStatus.RUNNING
    return StageStatus.PENDING


def stage_band_percent(stage: object, inner: float = 0.0) -> int:
    key = parse_stage_key(stage).value
    start, end = STAGE_PERCENT_BANDS.get(key, (0, 100))
    clamped = min(max(float(inner), 0.0), 1.0)
    return int(round(start + (end - start) * clamped))


def next_stage(stage: object) -> StageKey | None:
    current = parse_stage_key(stage)
    order = list(STAGE_ORDER)
    try:
        index = order.index(current)
    except ValueError:
        return StageKey.STARTUP
    if index + 1 >= len(order):
        return None
    return order[index + 1]


def previous_stages(stage: object) -> tuple[StageKey, ...]:
    current = parse_stage_key(stage)
    collected: list[StageKey] = []
    for key in STAGE_ORDER:
        if key == current:
            break
        collected.append(key)
    return tuple(collected)
