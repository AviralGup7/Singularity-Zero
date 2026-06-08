"""Burp Suite HTTP replay file loader."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class RequestResponse:
    request: dict[str, Any]
    response: dict[str, Any]
    response_time_seconds: float
    comment: str = ""


def import_http_history(path: str) -> list[RequestResponse]:
    records: list[RequestResponse] = []
    with open(path, encoding="utf-8") as fh:
        payload = json.load(fh)
    if isinstance(payload, dict):
        items = payload.get("items") or payload.get("requests") or payload.get("history") or []
    elif isinstance(payload, list):
        items = payload
    else:
        items = []
    for item in items:
        if not isinstance(item, dict):
            continue
        req = item.get("request") or item.get("req") or {}
        resp = item.get("response") or item.get("res") or {}
        timing = item.get("timing") or item.get("response_time") or item.get("time_taken")
        if isinstance(timing, dict):
            timing = timing.get("seconds") or timing.get("ms")
        try:
            timing_value = float(timing) if timing is not None else 0.0
        except (TypeError, ValueError):
            timing_value = 0.0
        records.append(
            RequestResponse(
                request=req,
                response=resp,
                response_time_seconds=timing_value,
                comment=str(item.get("comment") or item.get("notes") or ""),
            )
        )
    return records


__all__ = ["RequestResponse", "import_http_history"]
