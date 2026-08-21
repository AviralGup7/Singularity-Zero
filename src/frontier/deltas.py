"""Build NeuralState deltas without talking to Redis."""

from __future__ import annotations

import time
from typing import Any

from src.frontier import new_state


def delta(
    *,
    subdomains: list[str] | None = None,
    urls: list[str] | None = None,
    findings: list[dict[str, Any]] | None = None,
    wal_id: str | None = None,
    node_id: str = "local",
    now: float | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "_ts": float(now if now is not None else time.time()),
        "_node_id": node_id,
    }
    if subdomains:
        payload["subdomains"] = list(dict.fromkeys(subdomains))
    if urls:
        payload["urls"] = list(dict.fromkeys(urls))
    if findings:
        payload["findings"] = findings
    if wal_id:
        payload["_wal_id"] = wal_id
    return payload


def apply_many(payloads: list[dict[str, Any]]) -> Any:
    state = new_state()
    for item in payloads:
        state.apply_delta(item)
    return state


def snapshot_counts(state: Any) -> dict[str, int]:
    snap = state.get_snapshot()
    return {
        "subdomains": len(snap.get("subdomains") or []),
        "urls": len(snap.get("urls") or []),
        "findings": len(snap.get("findings") or []),
    }


def finding_titles(state: Any) -> list[str]:
    snap = state.get_snapshot()
    titles: list[str] = []
    for item in snap.get("findings") or []:
        if isinstance(item, dict):
            titles.append(str(item.get("title") or item.get("id") or ""))
        else:
            titles.append(str(item))
    return titles
