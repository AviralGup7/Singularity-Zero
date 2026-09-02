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


def _pct_threshold(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, str(default)))
    except ValueError:
        return default


def classify_pressure(
    *,
    disk_pct: float,
    mem_pct: float | None = None,
    previous_level: PressureLevel | None = None,
    hysteresis_pct: float = 5.0,
) -> PressureLevel:
    """Map utilisation percentages onto WARN / PRESSURE / CRITICAL with Schmitt-trigger hysteresis.

    Prevents rapid oscillation and flapping across threshold boundaries (Item 14).
    Defaults: disk warn 85, pressure 92, critical 95; mem pressure 85, critical 92.
    """
    disk_warn = _pct_threshold("DISK_WARN_PCT", 85.0)
    disk_pressure = _pct_threshold("DISK_PRESSURE_PCT", 92.0)
    disk_critical = _pct_threshold("DISK_CRITICAL_PCT", 95.0)
    mem_pressure = _pct_threshold("MEM_PRESSURE_PCT", 85.0)
    mem_critical = _pct_threshold("MEM_CRITICAL_PCT", 92.0)

    prev = previous_level if previous_level is not None else _current_level

    # If currently CRITICAL, remain CRITICAL until below threshold - deadband
    if prev == PressureLevel.CRITICAL:
        if disk_pct >= (disk_critical - hysteresis_pct) or (
            mem_pct is not None and mem_pct >= (mem_critical - hysteresis_pct)
        ):
            return PressureLevel.CRITICAL

    # If currently PRESSURE, remain PRESSURE until below threshold - deadband
    if prev in {PressureLevel.PRESSURE, PressureLevel.CRITICAL}:
        if disk_pct >= (disk_pressure - hysteresis_pct) or (
            mem_pct is not None and mem_pct >= (mem_pressure - hysteresis_pct)
        ):
            return PressureLevel.PRESSURE

    level = PressureLevel.OK
    if disk_pct >= disk_warn:
        level = PressureLevel.WARN
    if disk_pct >= disk_pressure:
        level = PressureLevel.PRESSURE
    if disk_pct >= disk_critical:
        level = PressureLevel.CRITICAL
    if mem_pct is not None:
        if mem_pct >= mem_pressure and level in {PressureLevel.OK, PressureLevel.WARN}:
            level = PressureLevel.PRESSURE
        if mem_pct >= mem_critical:
            level = PressureLevel.CRITICAL
    return level


_current_level = PressureLevel.OK


def set_pressure_level(level: PressureLevel) -> None:
    global _current_level
    _current_level = level


def current_pressure_level() -> PressureLevel:
    return _current_level


def spill_first_active() -> bool:
    """True when I/O should prefer JSONL spill over outbox/DB."""
    if os.environ.get("SPILL_FIRST", "").strip().lower() in {"1", "true", "yes", "on"}:
        return True
    return current_pressure_level() in {PressureLevel.PRESSURE, PressureLevel.CRITICAL}


def inspect_pressure(
    *,
    wal_path: Path | str | None = None,
) -> tuple[ResourceSnapshot, PressureLevel, float]:
    snap = inspect_resources(wal_path=wal_path)
    target = Path(wal_path) if wal_path is not None else Path(tempfile.gettempdir())
    probe_dir = target if target.is_dir() else target.parent
    disk_pct = 0.0
    try:
        usage = shutil.disk_usage(probe_dir if probe_dir.exists() else Path("."))
        if usage.total:
            disk_pct = 100.0 * (1.0 - (usage.free / usage.total))
    except OSError:
        disk_pct = 100.0
    level = classify_pressure(disk_pct=disk_pct)
    set_pressure_level(level)
    return snap, level, disk_pct


__all__ = [
    "PressureLevel",
    "ResourceExhausted",
    "ResourceSnapshot",
    "assert_resources",
    "classify_pressure",
    "current_pressure_level",
    "inspect_pressure",
    "inspect_resources",
    "set_pressure_level",
    "spill_first_active",
]
