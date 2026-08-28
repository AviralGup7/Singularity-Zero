"""Fail-fast resource guardrails before OOM / disk-full.

Pre-flight: min free disk, min free mem, temp dir writable, wal path writable.
On breach refuse scan run with a precise reason (or enter survival).
"""

from __future__ import annotations

import logging
import os
import shutil
import tempfile
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

logger = logging.getLogger(__name__)


class PressureLevel(StrEnum):
    OK = "ok"
    WARN = "warn"
    PRESSURE = "pressure"
    CRITICAL = "critical"


class ResourceExhausted(RuntimeError):
    """Host cannot satisfy the minimum runtime resource contract."""


@dataclass(frozen=True, slots=True)
class ResourceSnapshot:
    free_disk_bytes: int
    free_mem_bytes: int | None
    temp_writable: bool
    wal_writable: bool
    ok: bool
    reason: str = ""


def _free_mem_bytes() -> int | None:
    try:
        if hasattr(os, "sysconf"):
            pages = os.sysconf("SC_AVPHYS_PAGES")
            page = os.sysconf("SC_PAGE_SIZE")
            if pages and page:
                return int(pages) * int(page)
    except (ValueError, OSError, AttributeError):
        return None
    return None


def inspect_resources(
    *,
    wal_path: Path | str | None = None,
    min_free_disk_bytes: int = 64 * 1024 * 1024,
    min_free_mem_bytes: int = 64 * 1024 * 1024,
) -> ResourceSnapshot:
    target = Path(wal_path) if wal_path is not None else Path(tempfile.gettempdir())
    probe_dir = target if target.is_dir() else target.parent
    try:
        usage = shutil.disk_usage(probe_dir if probe_dir.exists() else Path("."))
        free_disk = int(usage.free)
    except OSError as exc:
        return ResourceSnapshot(0, None, False, False, False, f"disk_stat_failed:{exc}")

    free_mem = _free_mem_bytes()
    temp_writable = os.access(tempfile.gettempdir(), os.W_OK)
    wal_writable = (
        os.access(probe_dir, os.W_OK) if probe_dir.exists() else probe_dir.parent.exists()
    )

    reasons: list[str] = []
    if free_disk < min_free_disk_bytes:
        reasons.append(f"disk_free={free_disk}<{min_free_disk_bytes}")
    if free_mem is not None and free_mem < min_free_mem_bytes:
        reasons.append(f"mem_free={free_mem}<{min_free_mem_bytes}")
    if not temp_writable:
        reasons.append("temp_dir_not_writable")
    if not wal_writable:
        reasons.append("wal_path_not_writable")
    ok = not reasons
    return ResourceSnapshot(
        free_disk_bytes=free_disk,
        free_mem_bytes=free_mem,
        temp_writable=temp_writable,
        wal_writable=wal_writable,
        ok=ok,
        reason=",".join(reasons),
    )


def assert_resources(**kwargs: object) -> ResourceSnapshot:
    snap = inspect_resources(**kwargs)  # type: ignore[arg-type]
    if not snap.ok:
        raise ResourceExhausted(snap.reason)
    return snap


__all__ = ["ResourceExhausted", "ResourceSnapshot", "assert_resources", "inspect_resources"]
