"""Diff two job summaries for scan-vs-scan views."""

from __future__ import annotations

from typing import Any

from src.jobs.status import parse_job_status


def _counts(job: dict[str, Any]) -> dict[str, int]:
    return {
        "findings": int(job.get("findings_count") or 0),
        "critical": int(job.get("critical_findings") or 0),
        "high": int(job.get("high_findings") or 0),
        "warnings": int(job.get("warning_count") or 0),
    }


def diff_jobs(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    left_counts = _counts(left)
    right_counts = _counts(right)
    return {
        "left_id": left.get("id"),
        "right_id": right.get("id"),
        "status_changed": parse_job_status(left.get("status"))
        is not parse_job_status(right.get("status")),
        "findings_delta": right_counts["findings"] - left_counts["findings"],
        "critical_delta": right_counts["critical"] - left_counts["critical"],
        "high_delta": right_counts["high"] - left_counts["high"],
        "warnings_delta": right_counts["warnings"] - left_counts["warnings"],
        "left": left_counts,
        "right": right_counts,
    }


def improved(diff: dict[str, Any]) -> bool:
    return int(diff.get("critical_delta") or 0) < 0 or int(diff.get("findings_delta") or 0) < 0
