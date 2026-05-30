"""HTML helpers for collaborative triage audit summaries."""

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any, cast


def load_triage_events(output_root: Path, run_id: str | None = None) -> list[dict[str, Any]]:
    audit_path = Path(output_root) / "_triage" / "triage_audit.jsonl"
    if not audit_path.exists():
        return []
    events: list[dict[str, Any]] = []
    with audit_path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            event = json.loads(line)
            if run_id and event.get("run_id") != run_id:
                continue
            events.append(event)
    return events


def triage_audit_section(output_root: Path, run_id: str | None = None, limit: int = 25) -> str:
    events = load_triage_events(output_root, run_id=run_id)[-limit:]
    if not events:
        return (
            "<section><h2>Collaborative Triage Audit</h2>"
            "<p class='muted'>No collaborative triage actions recorded for this run.</p></section>"
        )
    rows = []
    for event in reversed(events):
        payload = (
            cast(dict[str, Any], event.get("payload"))
            if isinstance(event.get("payload"), dict)
            else {}
        )
        note = payload.get("text") or payload.get("reason") or payload.get("status") or ""
        rows.append(
            "<li class='finding-card'>"
            "<div class='finding-head'>"
            f"<strong>{html.escape(str(event.get('action', 'triage_action')).replace('_', ' ').title())}</strong>"
            f"<span class='muted'>by {html.escape(str(event.get('analyst_name', 'Analyst')))} | {html.escape(str(event.get('timestamp', '')))}</span>"
            "</div>"
            f"<span class='muted'>Finding: {html.escape(str(event.get('finding_id', '')))}</span><br>"
            f"{html.escape(str(note))}"
            f"<div class='meta'>hash {html.escape(str(event.get('hash', ''))[:16])}...</div>"
            "</li>"
        )
    return f"<section><h2>Collaborative Triage Audit</h2><ul>{''.join(rows)}</ul></section>"
