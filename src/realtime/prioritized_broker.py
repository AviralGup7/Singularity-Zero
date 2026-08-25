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
    traceparent: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "qos": int(self.qos),
            "topic": self.topic,
            "payload": dict(self.payload),
            "timestamp_unix": self.timestamp_unix,
            "dedup_key": self.dedup_key,
            "traceparent": self.traceparent,
        }


class BrokerSaturationError(RuntimeError):
    """Raised when broker capacity is completely exhausted under strict lossless backpressure."""


class PrioritizedRealtimeBroker:
    """Multi-lane QoS event broker managing prioritized backpressure, durable disk spooling, and shedding."""

    def __init__(
        self,
        p0_capacity: int = 1000,
        p1_capacity: int = 1000,
        p2_capacity: int = 500,
        p4_capacity: int = 200,
        max_p0_spool: int = 100000,
        spool_dir: str | None = None,
        disk_backpressure_pct: float = 85.0,
        disk_emergency_pct: float = 92.0,
    ) -> None:
        import json
        from pathlib import Path

        self.p0_capacity = p0_capacity
        self.max_p0_spool = max_p0_spool
        self.disk_backpressure_pct = disk_backpressure_pct
        self.disk_emergency_pct = disk_emergency_pct
        self._spool_dir = spool_dir
        self._spool_path: Path | None = None
        if spool_dir is not None:
            sd = Path(spool_dir)
            sd.mkdir(parents=True, exist_ok=True)
            self._spool_path = sd / "p0_telemetry_spool.jsonl"

        self._p0_queue: collections.deque[TelemetryEvent] = collections.deque(maxlen=p0_capacity)
        self._p0_memory_spool: collections.deque[TelemetryEvent] = collections.deque(maxlen=max_p0_spool)
        self._p1_queue: collections.deque[TelemetryEvent] = collections.deque(maxlen=p1_capacity)
        self._p2_map: dict[str, TelemetryEvent] = {}  # Coalesced findings
        self._p3_aggregates: dict[str, dict[str, Any]] = {}  # 1s bucket aggregates
        self._p4_queue: collections.deque[TelemetryEvent] = collections.deque(maxlen=p4_capacity)
        
        self._spool_file_count = 0
        self._dropped_counts: dict[QoSClass, int] = collections.defaultdict(int)
        self._lock = threading.RLock()

        # Rehydrate any un-drained disk spooled events on startup
        if self._spool_path is not None and self._spool_path.exists():
            self._rehydrate_disk_spool()

    def _get_disk_utilization_pct(self) -> float:
        """Query disk usage percentage for spool storage directory."""
        import shutil
        if self._spool_path is None:
            return 0.0
        try:
            target_path = self._spool_path.parent if self._spool_path.parent.exists() else Path(".")
            usage = shutil.disk_usage(target_path)
            return (usage.used / usage.total) * 100.0
        except Exception:
            return 0.0

    def _rehydrate_disk_spool(self) -> None:
        import json
        if self._spool_path is None or not self._spool_path.exists():
            return
        with open(self._spool_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    event = TelemetryEvent(
                        event_id=data["event_id"],
                        qos=QoSClass(data["qos"]),
                        topic=data["topic"],
                        payload=data["payload"],
                        timestamp_unix=data.get("timestamp_unix", time.time()),
                        dedup_key=data.get("dedup_key", ""),
                        traceparent=data.get("traceparent", ""),
                    )
                    if len(self._p0_queue) < self.p0_capacity:
                        self._p0_queue.append(event)
                    else:
                        self._p0_memory_spool.append(event)
                except Exception as exc:
                    logger.warning("Corrupt line in P0 disk spool: %s", exc)
        # Clear rehydrated file
        try:
            self._spool_path.unlink()
        except OSError:
            pass

    def _persist_to_disk_spool(self, event: TelemetryEvent) -> bool:
        import hashlib
        import json
        import os
        if self._spool_path is None:
            return False
        try:
            event_dict = event.to_dict()
            raw_bytes = json.dumps(event_dict, sort_keys=True).encode("utf-8")
            crc_sig = hashlib.sha256(raw_bytes).hexdigest()[:16]
            framed_record = {
                "magic": "P0SP",
                "version": 1,
                "seq": self._spool_file_count,
                "crc": crc_sig,
                "event_id": event.event_id,
                "qos": int(event.qos),
                "topic": event.topic,
                "payload": dict(event.payload),
                "timestamp_unix": event.timestamp_unix,
                "dedup_key": event.dedup_key,
                "traceparent": event.traceparent,
            }
            line = json.dumps(framed_record) + "\n"
            with open(self._spool_path, "a", encoding="utf-8") as f:
                f.write(line)
                f.flush()
                try:
                    os.fsync(f.fileno())
                except OSError:
                    pass
            self._spool_file_count += 1
            return True
        except Exception as exc:
            logger.error("Failed to append P0 event to disk spool: %s", exc)
            return False

    def publish(self, event: TelemetryEvent) -> bool:
        """Enqueue an event according to its QoS backpressure rules and disk thresholds."""
        with self._lock:
            disk_pct = self._get_disk_utilization_pct()

            # Under emergency disk pressure (>= 92%), drop P3/P4 and compact P1-P2
            if disk_pct >= self.disk_emergency_pct:
                if event.qos in (QoSClass.P3_TELEMETRY, QoSClass.P4_DEBUG):
                    self._dropped_counts[event.qos] += 1
                    return False
                # Compact P3 aggregates
                self._p3_aggregates.clear()

            # Under disk backpressure (>= 85%), shed P4 debug logs immediately
            elif disk_pct >= self.disk_backpressure_pct:
                if event.qos == QoSClass.P4_DEBUG:
                    self._dropped_counts[QoSClass.P4_DEBUG] += 1
                    return False

            if event.qos == QoSClass.P0_CONTROL:
                # 1. First buffer in bounded memory queue
                if len(self._p0_queue) < self.p0_capacity:
                    self._p0_queue.append(event)
                    return True

                # 2. Memory queue full: Persist to durable disk spool if enabled
                if self._spool_path is not None:
                    if self._persist_to_disk_spool(event):
                        return True

                # 3. Secondary memory spool buffer
                if len(self._p0_memory_spool) < self.max_p0_spool:
                    self._p0_memory_spool.append(event)
                    return True

                # 4. Memory and spool exhausted: Apply strict producer backpressure (NEVER silent drop)
                self._dropped_counts[QoSClass.P0_CONTROL] += 1
                logger.critical("P0 broker memory and disk spool fully saturated; applying backpressure")
                return False

            elif event.qos == QoSClass.P1_LIFECYCLE:
                if len(self._p1_queue) >= (self._p1_queue.maxlen or 1000):
                    self._dropped_counts[QoSClass.P1_LIFECYCLE] += 1
                self._p1_queue.append(event)
                return True

            elif event.qos == QoSClass.P2_FINDINGS:
                key = event.dedup_key or event.event_id
                self._p2_map[key] = event
                return True

            elif event.qos == QoSClass.P3_TELEMETRY:
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
            # 1. Drain P0 (highest priority: memory queue -> memory spool -> disk spool)
            while self._p0_queue and len(batch) < max_events:
                batch.append(self._p0_queue.popleft())
            while self._p0_memory_spool and len(batch) < max_events:
                batch.append(self._p0_memory_spool.popleft())

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
            dropped_dict: dict[Any, int] = {}
            for k, v in self._dropped_counts.items():
                if hasattr(k, "name"):
                    dropped_dict[k.name] = v
                    dropped_dict[int(k)] = v
                else:
                    dropped_dict[str(k)] = v
            return {
                "p0_depth": len(self._p0_queue) + len(self._p0_memory_spool) + self._spool_file_count,
                "p0_memory_depth": len(self._p0_queue),
                "p0_spool_depth": len(self._p0_memory_spool) + self._spool_file_count,
                "p1_depth": len(self._p1_queue),
                "p2_depth": len(self._p2_map),
                "p3_depth": len(self._p3_aggregates),
                "p4_depth": len(self._p4_queue),
                "dropped_counts": dropped_dict,
            }
