"""Realtime triage collaboration state and durable audit chain."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import threading
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from starlette.websockets import WebSocket, WebSocketState

logger = logging.getLogger(__name__)

TRIAGE_ACTIONS = {
    "comment_added",
    "comment_updated",
    "comment_deleted",
    "finding_annotated",
    "finding_escalated",
    "finding_closed",
    "finding_reopened",
    "finding_false_positive",
    "ai_false_positive_review",
}


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _canonical_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def merge_note_text(existing: str, incoming: str) -> str:
    """Merge concurrent note edits as an ordered, duplicate-free line set."""
    lines: list[str] = []
    seen: set[str] = set()
    for raw in [*existing.splitlines(), *incoming.splitlines()]:
        line = raw.strip()
        if not line or line in seen:
            continue
        seen.add(line)
        lines.append(line)
    return "\n".join(lines)


@dataclass
class TriageConnection:
    websocket: WebSocket
    run_id: str
    analyst_id: str
    analyst_name: str
    connection_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    finding_id: str | None = None
    cursor: dict[str, Any] = field(default_factory=dict)
    joined_at: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)

    def presence_payload(self) -> dict[str, Any]:
        return {
            "analyst_id": self.analyst_id,
            "analyst_name": self.analyst_name,
            "connection_id": self.connection_id,
            "finding_id": self.finding_id,
            "cursor": self.cursor,
            "joined_at": self.joined_at,
            "last_seen": self.last_seen,
        }


class TriageCollaborationService:
    """Append-only collaboration store plus in-process WebSocket fan-out."""

    def __init__(self, output_root: Path) -> None:
        self.output_root = Path(output_root)
        self.audit_dir = self.output_root / "_triage"
        self.audit_dir.mkdir(parents=True, exist_ok=True)
        self.audit_path = self.audit_dir / "triage_audit.jsonl"
        self._rooms: dict[str, dict[str, TriageConnection]] = defaultdict(dict)
        self._lock = asyncio.Lock()
        # Synchronous re-entrant lock for the audit chain write critical
        # section. We use a regular ``threading.RLock`` (not the async one)
        # because ``record_action`` is a sync method and we want to keep
        # callers (including sync tests) able to acquire it without an
        # event loop.
        self._write_lock = threading.RLock()

    async def connect(self, connection: TriageConnection) -> None:
        async with self._lock:
            self._rooms[connection.run_id][connection.connection_id] = connection
        await self.broadcast_presence(connection.run_id)

    async def disconnect(self, run_id: str, connection_id: str) -> None:
        async with self._lock:
            room = self._rooms.get(run_id)
            if room:
                room.pop(connection_id, None)
                if not room:
                    self._rooms.pop(run_id, None)
        await self.broadcast_presence(run_id)

    async def update_presence(
        self,
        run_id: str,
        connection_id: str,
        *,
        finding_id: str | None = None,
        cursor: dict[str, Any] | None = None,
    ) -> None:
        async with self._lock:
            connection = self._rooms.get(run_id, {}).get(connection_id)
            if not connection:
                return
            connection.last_seen = time.time()
            if finding_id is not None:
                connection.finding_id = finding_id
            if cursor is not None:
                connection.cursor = cursor
        await self.broadcast(
            run_id,
            {
                "type": "cursor",
                "run_id": run_id,
                "connection_id": connection_id,
                "analyst_id": connection.analyst_id,
                "analyst_name": connection.analyst_name,
                "finding_id": connection.finding_id,
                "cursor": connection.cursor,
                "timestamp": _utc_now(),
            },
            exclude={connection_id},
        )

    async def broadcast_presence(self, run_id: str) -> None:
        async with self._lock:
            analysts = [conn.presence_payload() for conn in self._rooms.get(run_id, {}).values()]
        await self.broadcast(
            run_id,
            {
                "type": "presence",
                "run_id": run_id,
                "analysts": analysts,
                "timestamp": _utc_now(),
            },
        )

    async def broadcast(
        self,
        run_id: str,
        payload: dict[str, Any],
        *,
        exclude: set[str] | None = None,
    ) -> int:
        exclude = exclude or set()
        async with self._lock:
            connections = list(self._rooms.get(run_id, {}).values())
        data = json.dumps(payload, ensure_ascii=False)

        async def _send_one(connection: TriageConnection) -> bool:
            if connection.connection_id in exclude:
                return False
            if connection.websocket.client_state != WebSocketState.CONNECTED:
                return False
            try:
                await connection.websocket.send_text(data)
                return True
            except Exception:  # noqa: S112
                return False

        results = await asyncio.gather(
            *[_send_one(conn) for conn in connections],
            return_exceptions=True,
        )
        return sum(1 for r in results if r is True)

    def record_action(
        self,
        *,
        run_id: str,
        finding_id: str,
        action: str,
        analyst_id: str,
        analyst_name: str,
        payload: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if action not in TRIAGE_ACTIONS:
            raise ValueError(f"Unsupported triage action: {action}")

        # The audit chain is built as a hash-linked list. Two concurrent
        # callers can read the same ``previous_hash``, both build valid
        # ``hash`` values, and then race to append — leaving the chain
        # forked and un-verifiable. We now serialise the read-then-write
        # window with a re-entrant lock scoped to this service.
        with self._write_lock:
            previous_hash = self.latest_hash()
            event = {
                "event_id": uuid.uuid4().hex,
                "run_id": run_id,
                "finding_id": finding_id,
                "action": action,
                "analyst_id": analyst_id,
                "analyst_name": analyst_name,
                "payload": payload or {},
                "timestamp": _utc_now(),
                "previous_hash": previous_hash,
            }
            event["hash"] = hashlib.sha256(
                f"{previous_hash}{_canonical_json(event)}".encode()
            ).hexdigest()
            with self.audit_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(event, ensure_ascii=False) + "\n")
        return event

    def latest_hash(self) -> str:
        latest = "0" * 64
        if not self.audit_path.exists():
            return latest
        try:
            with self.audit_path.open("r", encoding="utf-8") as handle:
                for line in handle:
                    if line.strip():
                        parsed_hash = json.loads(line).get("hash")
                        if parsed_hash:
                            latest = str(parsed_hash)
        except OSError as exc:
            logger.warning("Failed to read audit log %s: %s", self.audit_path, exc)
            return "0" * 64
        except json.JSONDecodeError as exc:
            logger.warning("Corrupt audit log entry in %s: %s", self.audit_path, exc)
        return latest

    def list_events(
        self,
        *,
        run_id: str | None = None,
        finding_id: str | None = None,
        limit: int = 200,
    ) -> list[dict[str, Any]]:
        if not self.audit_path.exists():
            return []
        events: list[dict[str, Any]] = []
        with self.audit_path.open("r", encoding="utf-8") as handle:
            for line in handle:
                if not line.strip():
                    continue
                event = json.loads(line)
                if run_id and event.get("run_id") != run_id:
                    continue
                if finding_id and event.get("finding_id") != finding_id:
                    continue
                events.append(event)
        return events[-limit:]

    def verify_chain(self) -> dict[str, Any]:
        previous_hash = "0" * 64
        count = 0
        if not self.audit_path.exists():
            return {"valid": True, "entries": 0, "latest_hash": previous_hash}
        with self.audit_path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                event = json.loads(line)
                recorded_hash = event.pop("hash", "")
                if event.get("previous_hash") != previous_hash:
                    return {"valid": False, "entries": count, "failed_at": line_number}
                computed = hashlib.sha256(
                    f"{previous_hash}{_canonical_json(event)}".encode()
                ).hexdigest()
                if computed != recorded_hash:
                    return {"valid": False, "entries": count, "failed_at": line_number}
                previous_hash = recorded_hash
                count += 1
        return {"valid": True, "entries": count, "latest_hash": previous_hash}

    def build_finding_state(self, run_id: str, finding_id: str) -> dict[str, Any]:
        events = self.list_events(run_id=run_id, finding_id=finding_id, limit=1000)
        comments: dict[str, dict[str, Any]] = {}
        status = "open"
        annotations: list[dict[str, Any]] = []

        for event in events:
            payload = cast(
                dict[str, Any],
                event.get("payload") if isinstance(event.get("payload"), dict) else {},
            )
            action = event.get("action")
            if action == "comment_added":
                comment_id = str(payload.get("comment_id") or event.get("event_id"))
                comments[comment_id] = {
                    "id": comment_id,
                    "finding_id": finding_id,
                    "author": event.get("analyst_name", "Analyst"),
                    "text": str(payload.get("text") or ""),
                    "mentions": payload.get("mentions") or [],
                    "parent_id": payload.get("parent_id"),
                    "timestamp": event.get("timestamp"),
                    "updated_at": event.get("timestamp"),
                }
            elif action == "comment_updated":
                comment_id = str(payload.get("comment_id") or "")
                if comment_id in comments:
                    comments[comment_id]["text"] = merge_note_text(
                        str(comments[comment_id].get("text") or ""),
                        str(payload.get("text") or ""),
                    )
                    comments[comment_id]["updated_at"] = event.get("timestamp")
            elif action == "comment_deleted":
                comments.pop(str(payload.get("comment_id") or ""), None)
            elif action == "finding_escalated":
                status = "escalated"
            elif action == "finding_closed":
                status = "closed"
            elif action == "finding_false_positive":
                status = "false_positive"
            elif action == "finding_reopened":
                status = "open"
            elif action == "finding_annotated":
                annotations.append(event)

        return {
            "run_id": run_id,
            "finding_id": finding_id,
            "status": status,
            "comments": sorted(comments.values(), key=lambda item: str(item.get("timestamp"))),
            "annotations": annotations,
            "audit": events,
            "chain": self.verify_chain(),
        }
