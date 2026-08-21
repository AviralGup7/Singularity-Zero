"""Stream frames pushed to a console connection."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from src.integration.correlation import new_event_id


@dataclass(slots=True)
class StreamFrame:
    type: str
    payload: dict[str, Any]
    event_id: str = field(default_factory=new_event_id)
    timestamp: float = field(default_factory=time.time)
    topic: str = "console"

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.event_id,
            "type": self.type,
            "topic": self.topic,
            "timestamp": self.timestamp,
            "payload": dict(self.payload),
        }

    @classmethod
    def heartbeat(cls) -> StreamFrame:
        return cls(type="heartbeat", payload={}, topic="connection")

    @classmethod
    def job(cls, event: dict[str, Any]) -> StreamFrame:
        return cls(type=str(event.get("type") or "job.event"), payload=dict(event), topic="jobs")

    @classmethod
    def notification(cls, item: dict[str, Any]) -> StreamFrame:
        return cls(type="notification", payload=dict(item), topic="notifications")


class FrameBuffer:
    def __init__(self, *, limit: int = 400) -> None:
        self._limit = max(32, int(limit))
        self._items: list[StreamFrame] = []

    def push(self, frame: StreamFrame) -> StreamFrame:
        self._items.append(frame)
        if len(self._items) > self._limit:
            self._items = self._items[-self._limit :]
        return frame

    def drain(self, *, after_id: str | None = None, limit: int = 100) -> list[StreamFrame]:
        items = list(self._items)
        if after_id:
            index = next((i for i, frame in enumerate(items) if frame.event_id == after_id), None)
            if index is not None:
                items = items[index + 1 :]
        return items[: max(1, min(int(limit), 200))]

    def __len__(self) -> int:
        return len(self._items)
