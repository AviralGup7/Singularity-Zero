"""Pure helpers for dashboard KPI assembly.

Kept out of ``app_factory`` so trend/stage math can be unit-tested without
importing FastAPI. Trend series are built only from job timestamps — never
synthesized from the current finding total.
"""

from __future__ import annotations

import re
import time
from datetime import datetime
from typing import Any

_DAY = 86400.0
_TOKEN_RE = re.compile(r"[a-z0-9]+")

# First matching bucket wins. More specific tokens are listed before "scan"
# so a stage named "recon-scan" is discovery, not collection.
_STAGE_TOKEN_BUCKETS: tuple[tuple[str, frozenset[str]], ...] = (
    ("discovery", frozenset({"subdomain", "recon", "discovery", "enumerate", "dns", "osint"})),
    ("analysis", frozenset({"analysis", "analyze", "passive", "nuclei", "semgrep"})),
    ("validation", frozenset({"valid", "validation", "validate", "verify", "exploit"})),
    ("reporting", frozenset({"report", "reporting", "writeup"})),
    ("collection", frozenset({"url", "urls", "crawl", "collect", "scan", "httpx", "katana"})),
)


def parse_epoch(value: Any) -> float | None:
    """Best-effort parse of ISO timestamps, epoch seconds, or epoch millis."""
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        num = float(value)
        if num > 1e12:
            num /= 1000.0
        return num if num > 0 else None
    text = str(value).strip()
    if not text:
        return None
    try:
        num = float(text)
        if num > 1e12:
            num /= 1000.0
        return num if num > 0 else None
    except ValueError:
        pass
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def classify_pipeline_stage(stage: Any) -> str:
    tokens = set(_TOKEN_RE.findall(str(stage or "").lower()))
    if not tokens:
        return "other"
    for bucket, keys in _STAGE_TOKEN_BUCKETS:
        if tokens & keys:
            return bucket
    return "other"


def build_stage_counts(jobs: list[dict[str, Any]]) -> dict[str, int]:
    counts = {
        "discovery": 0,
        "collection": 0,
        "analysis": 0,
        "validation": 0,
        "reporting": 0,
        "other": 0,
    }
    for job in jobs:
        bucket = classify_pipeline_stage(job.get("stage") or job.get("stage_label"))
        counts[bucket] = counts.get(bucket, 0) + 1
    return counts


def job_series(
    jobs: list[dict[str, Any]],
    *,
    buckets: int = 8,
    now: float | None = None,
) -> dict[str, Any]:
    """Bucket jobs into the last ``buckets`` days.

    ``trend_data`` is the sum of ``findings_count`` per day.
    ``scan_trend`` is jobs started per day.
    Returns empty series (not a fake descending curve) when no timestamp
    can be parsed.
    """
    size = max(1, buckets)
    now_ts = time.time() if now is None else now
    findings = [0] * size
    scans = [0] * size
    dated = 0
    for job in jobs:
        epoch = parse_epoch(
            job.get("started_at") or job.get("finished_at") or job.get("updated_at")
        )
        if epoch is None:
            continue
        dated += 1
        age = int((now_ts - epoch) // _DAY)
        if age < 0:
            idx = size - 1
        elif age >= size:
            continue
        else:
            idx = size - 1 - age
        scans[idx] += 1
        try:
            findings[idx] += int(job.get("findings_count") or 0)
        except (TypeError, ValueError):
            pass
    if dated == 0:
        return {"trend_data": [], "scan_trend": [], "trend_source": "empty"}
    return {"trend_data": findings, "scan_trend": scans, "trend_source": "jobs"}
