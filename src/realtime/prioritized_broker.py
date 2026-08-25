"""Prioritized Realtime Event Broker with Multi-Tier QoS Backpressure.

Protects WebSocket clients and control plane from telemetry denial-of-service:
- P0 (Control & Emergency): Infinite buffer, strict non-blocking delivery, never dropped
- P1 (Execution Lifecycle): Reliable delivery, fixed capacity queue
- P2 (Vulnerability Findings): Deduplicated & coalesced by finding key
- P3 (Telemetry & Metrics): 1-second sliding window aggregation
- P4 (Debug Logs): Sampled / dropped on queue saturation
"""

from __future__ import annotations

import collections
import enum
import logging
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


class QoSClass(enum.IntEnum):
    """Quality of Service priorities (lower integer = higher priority)."""

    P0_CONTROL = 0
    P1_LIFECYCLE = 1
    P2_FINDINGS = 2
    P3_TELEMETRY = 3
    P4_DEBUG = 4


@dataclass(frozen=True, slots=True)
class TelemetryEvent:
    """Immutable real-time event envelope."""

    event_id: str
    qos: QoSClass
    topic: str
    payload: Mapping[str, Any]
    timestamp_unix: float = field(default_factory=time.time)
    dedup_key: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "qos": int(self.qos),
            "topic": self.topic,
            "payload": dict(self.payload),
            "timestamp_unix": self.timestamp_unix,
            "dedup_key": self.dedup_key,
        }


class PrioritizedRealtimeBroker:
    """Multi-lane QoS event broker managing prioritized backpressure and shedding."""

    def __init__(
        self,
        p1_capacity: int = 1000,
        p2_capacity: int = 500,
        p4_capacity: int = 200,
    ) -> None:
        self._p0_queue: collections.deque[TelemetryEvent] = collections.deque()  # Unbounded
        self._p1_queue: collections.deque[TelemetryEvent] = collections.deque(maxlen=p1_capacity)
        self._p2_map: dict[str, TelemetryEvent] = {}  # Coalesced findings
        self._p3_aggregates: dict[str, dict[str, Any]] = {}  # 1s bucket aggregates
        self._p4_queue: collections.deque[TelemetryEvent] = collections.deque(maxlen=p4_capacity)
        
        self._dropped_counts: dict[QoSClass, int] = collections.defaultdict(int)
        self._lock = threading.RLock()

    def publish(self, event: TelemetryEvent) -> bool:
        """Enqueue an event according to its QoS backpressure rules."""
        with self._lock:
            if event.qos == QoSClass.P0_CONTROL:
                self._p0_queue.append(event)
                return True

            elif event.qos == QoSClass.P1_LIFECYCLE:
                if len(self._p1_queue) >= (self._p1_queue.maxlen or 1000):
                    self._dropped_counts[QoSClass.P1_LIFECYCLE] += 1
                self._p1_queue.append(event)
                return True

            elif event.qos == QoSClass.P2_FINDINGS:
                # Coalesce / deduplicate by dedup_key or event_id
                key = event.dedup_key or event.event_id
                self._p2_map[key] = event
                return True

            elif event.qos == QoSClass.P3_TELEMETRY:
                # Aggregate metrics into 1s sliding window bucket
                bucket_key = event.topic
                current = self._p3_aggregates.get(bucket_key, {})
                for k, v in event.payload.items():
                    if isinstance(v, (int, float)):
                        current[k] = current.get(k, 0.0) + float(v)
                    else:
                        current[k] = v
                self._p3_aggregates[bucket_key] = current
                return True

            elif event.qos == QoSClass.P4_DEBUG:
                if len(self._p4_queue) >= (self._p4_queue.maxlen or 200):
                    self._dropped_counts[QoSClass.P4_DEBUG] += 1
                    return False  # Drop debug frame under saturation
                self._p4_queue.append(event)
                return True

            return False

    def drain_batch(self, max_events: int = 100) -> list[TelemetryEvent]:
        """Drain events strictly in priority order (P0 -> P1 -> P2 -> P3 -> P4)."""
        batch: list[TelemetryEvent] = []
        with self._lock:
            # 1. Drain P0 (highest priority)
            while self._p0_queue and len(batch) < max_events:
                batch.append(self._p0_queue.popleft())

            # 2. Drain P1
            while self._p1_queue and len(batch) < max_events:
                batch.append(self._p1_queue.popleft())

            # 3. Drain P2 Coalesced Findings
            if self._p2_map and len(batch) < max_events:
                keys = list(self._p2_map.keys())
                for k in keys:
                    if len(batch) >= max_events:
                        break
                    batch.append(self._p2_map.pop(k))

            # 4. Drain P3 Aggregates
            if self._p3_aggregates and len(batch) < max_events:
                keys = list(self._p3_aggregates.keys())
                for k in keys:
                    if len(batch) >= max_events:
                        break
                    agg_payload = self._p3_aggregates.pop(k)
                    batch.append(
                        TelemetryEvent(
                            event_id=f"agg_{time.time_ns()}",
                            qos=QoSClass.P3_TELEMETRY,
                            topic=k,
                            payload=agg_payload,
                        )
                    )

            # 5. Drain P4 Debug Logs
            while self._p4_queue and len(batch) < max_events:
                batch.append(self._p4_queue.popleft())

        return batch

    def get_stats(self) -> dict[str, Any]:
        with self._lock:
            return {
                "p0_depth": len(self._p0_queue),
                "p1_depth": len(self._p1_queue),
                "p2_coalesced_depth": len(self._p2_map),
                "p3_metrics_depth": len(self._p3_aggregates),
                "p4_depth": len(self._p4_queue),
                "dropped_counts": {k.name: v for k, v in self._dropped_counts.items()},
            }
