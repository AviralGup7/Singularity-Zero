import json
import logging
from datetime import UTC, datetime
from typing import Any

logger = logging.getLogger(__name__)


def _find_finding_by_id(
    output_root: Any, finding_id: str, tenant_id: str | None = None
) -> dict[str, Any] | None:
    from pathlib import Path

    from src.dashboard.fastapi.routers.targets import is_target_owned_by_tenant

    index_path = Path(output_root) / "findings_index.json"
    if index_path.exists():
        try:
            index_data = json.loads(index_path.read_text(encoding="utf-8"))
            if finding_id in index_data:
                entry = index_data[finding_id]
                target_name = entry.get("target_name")
                run_name = entry.get("run_name")
                idx = entry.get("index")

                if is_target_owned_by_tenant(target_name, tenant_id):
                    finding_path = Path(output_root) / target_name / run_name / "findings.json"
                    if finding_path.exists():
                        findings = json.loads(finding_path.read_text(encoding="utf-8"))
                        if isinstance(findings, list) and 0 < idx <= len(findings):
                            finding = findings[idx - 1]
                            from src.dashboard.fastapi.routers.targets import (
                                _normalize_finding_payload,
                            )

                            return _normalize_finding_payload(
                                finding,
                                target_name=target_name,
                                run_name=run_name,
                                index=idx,
                            )
        except Exception:  # noqa: S110
            pass

    index_data = {}
    result = None
    if Path(output_root).exists():
        for target_entry in Path(output_root).iterdir():
            if not target_entry.is_dir() or target_entry.name.startswith("_"):
                continue
            for run_entry in target_entry.iterdir():
                if not run_entry.is_dir():
                    continue
                findings_path = run_entry / "findings.json"
                if not findings_path.exists():
                    continue
                try:
                    findings = json.loads(findings_path.read_text(encoding="utf-8"))
                except Exception:  # noqa: S112
                    continue
                if not isinstance(findings, list):
                    continue
                for idx, finding in enumerate(findings, start=1):
                    if not isinstance(finding, dict):
                        continue
                    fid = (
                        finding.get("id")
                        or finding.get("finding_id")
                        or f"{target_entry.name}-{run_entry.name}-{idx}"
                    )
                    index_data[str(fid)] = {
                        "target_name": target_entry.name,
                        "run_name": run_entry.name,
                        "index": idx,
                    }
                    if str(fid) == finding_id and is_target_owned_by_tenant(
                        target_entry.name, tenant_id
                    ):
                        from src.dashboard.fastapi.routers.targets import (
                            _normalize_finding_payload,
                        )

                        result = _normalize_finding_payload(
                            finding,
                            target_name=target_entry.name,
                            run_name=run_entry.name,
                            index=idx,
                        )

        try:
            index_path.write_text(json.dumps(index_data, indent=2), encoding="utf-8")
        except Exception:  # noqa: S110
            pass

    return result


def _collect_timeline_events(
    output_root: Any,
    *,
    job_id: str | None = None,
    job_target: str | None = None,
    severity: str | None = None,
    target: str | None = None,
    start_date: str | None = None,
    end_date: str | None = None,
    limit: int = 50,
    offset: int = 0,
    tenant_id: str | None = None,
) -> list[dict]:
    """Collect finding discovery events from pipeline output."""
    from pathlib import Path

    root = Path(output_root)
    events: list[dict] = []
    if not root.exists():
        return events
    severity_filter = (severity or "").lower() or None
    for target_entry in root.iterdir():
        if not target_entry.is_dir():
            continue
        tname = target_entry.name
        if target and tname != target:
            continue
        for run_entry in target_entry.iterdir():
            if not run_entry.is_dir():
                continue
            findings_path = run_entry / "findings.json"
            if not findings_path.exists():
                continue
            try:
                findings = json.loads(findings_path.read_text(encoding="utf-8"))
            except Exception:
                logger.warning("Failed to parse findings at %s", findings_path, exc_info=True)
                continue
            if not isinstance(findings, list):
                continue
            for idx, finding in enumerate(findings, 1):
                if not isinstance(finding, dict):
                    continue
                fsev = str(finding.get("severity", "")).lower()
                if severity_filter and fsev != severity_filter:
                    continue
                events.append(
                    {
                        "id": finding.get("finding_id") or f"{tname}:{run_entry.name}:{idx}",
                        "target_name": tname,
                        "run_name": run_entry.name,
                        "severity": fsev,
                        "title": finding.get("title", ""),
                        "timestamp": finding.get("timestamp") or run_entry.name,
                        "status": finding.get("status", "open"),
                    }
                )
    events.sort(key=lambda e: str(e.get("timestamp", "")), reverse=True)
    return events[offset : offset + limit]


def _seeded_timeline_events(limit: int = 10, offset: int = 0) -> list[dict]:
    """Return synthetic seed events when no real events are found."""
    base_ts = datetime.now(UTC).isoformat()
    seeds = [
        {
            "id": "seed-1",
            "target_name": "example.com",
            "run_name": "baseline",
            "severity": "info",
            "title": "System initialized",
            "timestamp": base_ts,
            "status": "info",
        },
        {
            "id": "seed-2",
            "target_name": "example.com",
            "run_name": "baseline",
            "severity": "low",
            "title": "Baseline scan complete",
            "timestamp": base_ts,
            "status": "completed",
        },
    ]
    return seeds[offset : offset + limit]


def _telemetry_timeline_events(
    jobs: list[dict],
    *,
    job_id: str | None = None,
    severity: str | None = None,
    target: str | None = None,
    start_date: str | None = None,
    end_date: str | None = None,
    tenant_id: str | None = None,
) -> list[dict]:
    """Extract timeline events from in-memory job list (no real events found)."""
    events: list[dict] = []
    severity_filter = (severity or "").lower() or None
    for job in jobs or []:
        jid = str(job.get("job_id", "") or "")
        if job_id and jid != job_id:
            continue
        jtarget = str(job.get("target_name", "") or "")
        if target and jtarget != target:
            continue
        jsev = str(job.get("severity", "info") or "info").lower()
        if severity_filter and jsev != severity_filter:
            continue
        events.append(
            {
                "id": jid,
                "target_name": jtarget,
                "run_name": jid,
                "severity": jsev,
                "title": str(job.get("stage", "") or "Unknown stage"),
                "timestamp": job.get("started_at") or job.get("updated_at") or "",
                "status": str(job.get("status", "") or "unknown"),
            }
        )
    events.sort(key=lambda e: str(e.get("timestamp", "")), reverse=True)
    return events
