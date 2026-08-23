"""Batch several commands in one round trip."""

from __future__ import annotations

from typing import Any

from src.integration.errors import bad_request

MAX_BATCH = 8


def parse_batch(payload: dict[str, Any]) -> list[dict[str, Any]]:
    raw = payload.get("commands") or payload.get("items") or []
    if not isinstance(raw, list):
        raise bad_request("batch commands must be a list")
    if len(raw) > MAX_BATCH:
        raise bad_request("batch too large", limit=MAX_BATCH, received=len(raw))
    items: list[dict[str, Any]] = []
    for entry in raw:
        if not isinstance(entry, dict):
            raise bad_request("batch entry must be an object")
        command = str(entry.get("command") or "").strip()
        if not command:
            raise bad_request("batch entry missing command")
        if command == "batch.execute":
            raise bad_request("nested batch is not allowed")
        items.append(
            {
                "command": command,
                "payload": dict(entry.get("payload") or {})
                if isinstance(entry.get("payload"), dict)
                else {},
                "path_params": {
                    str(k): str(v) for k, v in dict(entry.get("path_params") or {}).items()
                },
            }
        )
    return items
