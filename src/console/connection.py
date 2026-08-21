"""Live console connections: handshake identity + event buffer."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field

from src.integration.correlation import new_connection_id
from src.integration.events import FrameBuffer, StreamFrame


@dataclass(slots=True)
class ConsoleConnection:
    connection_id: str
    subject: str
    protocol: str
    kind: str
    created_at: float
    last_seen: float
    topics: set[str] = field(default_factory=lambda: {"jobs", "notifications", "connection"})
    frames: FrameBuffer = field(default_factory=FrameBuffer)

    def touch(self, *, now: float | None = None) -> None:
        self.last_seen = float(now if now is not None else time.time())

    def subscribe(self, topic: str) -> None:
        self.topics.add(str(topic))

    def publish(self, frame: StreamFrame) -> None:
        if frame.topic in self.topics or frame.topic == "connection":
            self.frames.push(frame)

    def poll(self, *, after_id: str | None = None, limit: int = 50) -> list[dict[str, object]]:
        return [frame.to_dict() for frame in self.frames.drain(after_id=after_id, limit=limit)]


class ConnectionRegistry:
    def __init__(self, *, ttl_seconds: float = 3600.0) -> None:
        self._ttl = max(60.0, float(ttl_seconds))
        self._lock = threading.RLock()
        self._items: dict[str, ConsoleConnection] = {}

    def _purge(self, now: float) -> None:
        expired = [key for key, conn in self._items.items() if now - conn.last_seen > self._ttl]
        for key in expired:
            self._items.pop(key, None)

    def open(
        self,
        *,
        subject: str,
        protocol: str,
        kind: str,
        now: float | None = None,
    ) -> ConsoleConnection:
        epoch = float(now if now is not None else time.time())
        conn = ConsoleConnection(
            connection_id=new_connection_id(),
            subject=subject,
            protocol=protocol,
            kind=kind,
            created_at=epoch,
            last_seen=epoch,
        )
        with self._lock:
            self._purge(epoch)
            self._items[conn.connection_id] = conn
        return conn

    def get(self, connection_id: str | None) -> ConsoleConnection | None:
        if not connection_id:
            return None
        with self._lock:
            self._purge(time.time())
            return self._items.get(connection_id)

    def close(self, connection_id: str) -> bool:
        with self._lock:
            return self._items.pop(connection_id, None) is not None

    def touch(self, connection_id: str | None, *, now: float | None = None) -> ConsoleConnection | None:
        conn = self.get(connection_id)
        if conn is None:
            return None
        conn.touch(now=now)
        return conn

    def publish(self, frame: StreamFrame, *, subject: str | None = None) -> int:
        delivered = 0
        with self._lock:
            for conn in self._items.values():
                if subject and conn.subject != subject:
                    continue
                conn.publish(frame)
                delivered += 1
        return delivered

    def __len__(self) -> int:
        with self._lock:
            return len(self._items)
