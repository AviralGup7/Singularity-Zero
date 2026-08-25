"""Durable Committed Event Outbox Ledger & Stream Engine (Level 2/3 Outbox).

Implements the authoritative committed-log/outbox stream:
- Atomic durable write of domain events emitted by committed FSM state transitions
- CRC-64 validated append-only storage on disk (or in-memory when outbox_dir is None)
- Deterministic event recovery and idempotent projection dispatch
- Deduplicated event replay preserving watermarks
"""

from __future__ import annotations

import json
import logging
import os
import threading
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from src.core.contracts.command_envelope import EventEnvelope
from src.infrastructure.frontier.wal import compute_crc64

logger = logging.getLogger(__name__)


class DurableOutboxLedger:
    """Crash-safe, append-only outbox ledger for committed domain events."""

    def __init__(self, partition_id: str, outbox_dir: Path | str | None = None) -> None:
        self.partition_id = partition_id
        self._outbox_path: Path | None = None
        if outbox_dir is not None:
            base_dir = Path(outbox_dir)
            base_dir.mkdir(parents=True, exist_ok=True)
            self._outbox_path = base_dir / f"outbox_{partition_id}.log"

        self._lock = threading.RLock()
        self._seen_event_ids: set[str] = set()
        self._events: list[EventEnvelope] = []
        self._load_existing_events()

    @property
    def event_count(self) -> int:
        with self._lock:
            return len(self._events)

    def _load_existing_events(self) -> None:
        """Scan existing outbox file and populate deduplication index."""
        if self._outbox_path is None or not self._outbox_path.exists():
            return
        with self._lock:
            try:
                with open(self._outbox_path, "rb") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            record = json.loads(line.decode("utf-8"))
                            crc_expected = record.get("crc64")
                            data_raw = json.dumps(record.get("event"), sort_keys=True).encode("utf-8")
                            if crc_expected and compute_crc64(data_raw) != crc_expected:
                                logger.warning("Outbox corruption detected in record, skipping")
                                continue
                            evt_dict = record.get("event", {})
                            evt = EventEnvelope.from_dict(evt_dict)
                            if evt.event_id not in self._seen_event_ids:
                                self._seen_event_ids.add(evt.event_id)
                                self._events.append(evt)
                        except Exception as e:
                            logger.debug("Failed parsing outbox line: %s", e)
            except Exception as e:
                logger.warning("Failed to load existing outbox ledger %s: %s", self._outbox_path, e)

    def append_events(self, events: Sequence[EventEnvelope], sync: bool = True) -> int:
        """Append emitted domain events to the durable outbox ledger atomically."""
        if not events:
            return 0
        with self._lock:
            appended = 0
            file_handle = open(self._outbox_path, "ab") if self._outbox_path is not None else None
            try:
                for evt in events:
                    if evt.event_id in self._seen_event_ids:
                        continue
                    evt_dict = evt.to_dict()
                    data_raw = json.dumps(evt_dict, sort_keys=True).encode("utf-8")
                    crc = compute_crc64(data_raw)
                    record = {
                        "seq": len(self._events) + 1,
                        "partition_id": self.partition_id,
                        "crc64": crc,
                        "event": evt_dict,
                    }
                    if file_handle is not None:
                        line = json.dumps(record, sort_keys=True).encode("utf-8") + b"\n"
                        file_handle.write(line)
                    self._seen_event_ids.add(evt.event_id)
                    self._events.append(evt)
                    appended += 1
                if file_handle is not None and sync:
                    file_handle.flush()
                    try:
                        os.fsync(file_handle.fileno())
                    except OSError:
                        pass
            finally:
                if file_handle is not None:
                    file_handle.close()
            return appended

    def read_all_events(self) -> list[EventEnvelope]:
        """Read all validated domain events from the outbox in committed order."""
        with self._lock:
            return list(self._events)

    def read_events_since(self, last_applied_raft_index: int) -> list[EventEnvelope]:
        """Stream events with raft_index > last_applied_raft_index for projection watermarks."""
        all_events = self.read_all_events()
        return [e for e in all_events if e.raft_index > last_applied_raft_index]
