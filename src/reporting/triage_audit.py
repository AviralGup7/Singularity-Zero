"""Collaborative triage audit tracking, workload distribution, and CSV/JSON export."""

from __future__ import annotations

import csv
import html
import json
from pathlib import Path
from typing import Any, cast


def load_triage_events(output_root: Path, run_id: str | None = None) -> list[dict[str, Any]]:
    """Load logged collaborative triage events from JSONL audit log."""
    audit_path = Path(output_root) / "_triage" / "triage_audit.jsonl"
    if not audit_path.exists():
        return []
    events: list[dict[str, Any]] = []
    with audit_path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError as exc:
                import logging

                logging.getLogger(__name__).warning(
                    "Malformed JSONL line in triage audit log: %s", exc
                )
                continue
            if run_id and event.get("run_id") != run_id:
                continue
            events.append(event)
    return events


def bulk_triage_findings(
    output_root: Path,
    finding_ids: list[str],
    status: str,
    analyst_name: str,
    reason: str,
    role: str = "Analyst",
) -> int:
    """Record a collaborative bulk triage event for multiple finding IDs."""
    import time

    audit_dir = Path(output_root) / "_triage"
    audit_dir.mkdir(parents=True, exist_ok=True)
    audit_path = audit_dir / "triage_audit.jsonl"

    event = {
        "timestamp": int(time.time()),
        "action": "bulk_triage",
        "analyst_name": analyst_name,
        "analyst_role": role,
        "finding_ids": finding_ids,
        "payload": {
            "status": status,
            "reason": reason,
        },
    }

    with audit_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event) + "\n")

    return len(finding_ids)


def calculate_team_triage_metrics(events: list[dict[str, Any]], findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Compute triage team workload, aging backlog, and throughput telemetry."""
    analyst_workload: dict[str, int] = {}
    total_time_to_triage = 0.0
    triaged_count = 0
    backlog_count = 0
    assigned_count = 0

    for event in events:
        analyst = event.get("analyst_name", "Unassigned")
        analyst_workload[analyst] = analyst_workload.get(analyst, 0) + 1

    for finding in findings:
        status = str(finding.get("status") or finding.get("triage_status") or "OPEN").upper()
        if status in {"OPEN", "UNRESOLVED", "NEW"}:
            backlog_count += 1
        else:
            triaged_count += 1

        assignee = finding.get("assignee")
        if assignee:
            assigned_count += 1

        disc_at = finding.get("discovered_at") or finding.get("timestamp")
        triaged_at = finding.get("triaged_at")
        if disc_at and triaged_at:
            try:
                diff = float(triaged_at) - float(disc_at)
                if diff > 0:
                    total_time_to_triage += diff
            except (ValueError, TypeError):
                pass

    avg_triage_hours = 0.0
    if triaged_count > 0:
        avg_triage_hours = round((total_time_to_triage / triaged_count) / 3600.0, 2)

    return {
        "analyst_workload": analyst_workload,
        "avg_triage_hours": avg_triage_hours,
        "backlog_count": backlog_count,
        "assigned_count": assigned_count,
        "triaged_count": triaged_count,
    }


def export_triage_queue_csv(findings: list[dict[str, Any]], output_path: Path) -> Path:
    """Export the current manual verification and triage queue to a CSV artifact."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    headers = ["ID", "Title", "Severity", "Category", "URL", "Status", "Assignee", "Triage_SLA"]

    with output_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        for f_item in findings:
            writer.writerow([
                f_item.get("id", ""),
                f_item.get("title", ""),
                f_item.get("severity", ""),
                f_item.get("category", ""),
                f_item.get("url", ""),
                f_item.get("status", "OPEN"),
                f_item.get("assignee", "Unassigned"),
                f_item.get("sla_status", "N/A")
            ])
    return output_path


def export_triage_queue_json(findings: list[dict[str, Any]], output_path: Path) -> Path:
    """Export the current manual verification and triage queue to a JSON artifact."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(findings, f, indent=2, ensure_ascii=False)
    return output_path


def triage_audit_section(output_root: Path, run_id: str | None = None, limit: int = 25) -> str:
    """Render the collaborative triage audit section including team metrics scorecard."""
    events = load_triage_events(output_root, run_id=run_id)

    findings = []
    findings_path = Path(output_root) / "findings.json"
    if run_id:
        findings_path = Path(output_root) / run_id / "findings.json"

    if findings_path.exists():
        try:
            findings = json.loads(findings_path.read_text(encoding="utf-8"))
        except Exception:
            pass

    metrics = calculate_team_triage_metrics(events, findings)

    # Render GRC / Team workload scorecard
    workload_items = []
    for name, val in metrics["analyst_workload"].items():
        workload_items.append(f"<li>{html.escape(name)}: {val} actions</li>")
    workload_str = "".join(workload_items) if workload_items else "<li>No active allocations</li>"

    scorecard_html = f"""
    <div class='triage-scorecard' style='display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin-bottom: 25px; background: #fafafa; padding: 20px; border-radius: 8px; border: 1px solid #ddd; font-family: sans-serif;'>
        <div>
            <span style='font-size: 11px; text-transform: uppercase; color: #666; display: block;'>Triage Backlog</span>
            <strong style='font-size: 24px; color: #222;'>{metrics["backlog_count"]}</strong>
        </div>
        <div>
            <span style='font-size: 11px; text-transform: uppercase; color: #666; display: block;'>Active Assignments</span>
            <strong style='font-size: 24px; color: #222;'>{metrics["assigned_count"]}</strong>
        </div>
        <div>
            <span style='font-size: 11px; text-transform: uppercase; color: #666; display: block;'>Avg Time-to-Triage</span>
            <strong style='font-size: 24px; color: #222;'>{metrics["avg_triage_hours"]} hrs</strong>
        </div>
        <div>
            <span style='font-size: 11px; text-transform: uppercase; color: #666; display: block;'>Workload Allocation</span>
            <ul style='font-size: 11px; color: #222; margin: 5px 0 0 0; padding-left: 15px;'>
                {workload_str}
            </ul>
        </div>
    </div>
    """

    if not events:
        return (
            f"<section><h2>Collaborative Triage Audit</h2>"
            f"{scorecard_html}"
            f"<p class='muted'>No collaborative triage actions recorded for this run.</p></section>"
        )

    rows = []
    for event in reversed(events[-limit:]):
        payload = (
            cast(dict[str, Any], event.get("payload"))
            if isinstance(event.get("payload"), dict)
            else {}
        )
        note = payload.get("text") or payload.get("reason") or payload.get("status") or ""
        role = event.get("analyst_role", "Analyst")

        fids = event.get("finding_ids")
        finding_id_str = event.get("finding_id", "")
        if fids:
            finding_id_str = f"Bulk ({len(fids)} items)"

        rows.append(
            "<li class='finding-card'>"
            "<div class='finding-head'>"
            f"<strong>{html.escape(str(event.get('action', 'triage_action')).replace('_', ' ').title())}</strong>"
            f"<span class='muted'>by {html.escape(str(event.get('analyst_name', 'Analyst')))} ({html.escape(role)}) | {html.escape(str(event.get('timestamp', '')))}</span>"
            "</div>"
            f"<span class='muted'>Finding: {html.escape(str(finding_id_str))}</span><br>"
            f"{html.escape(str(note))}"
            f"<div class='meta'>hash {html.escape(str(event.get('hash', ''))[:16])}...</div>"
            "</li>"
        )
    return f"<section><h2>Collaborative Triage Audit</h2>{scorecard_html}<ul>{''.join(rows)}</ul></section>"
