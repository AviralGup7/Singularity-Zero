"""
Cyber Security Test Pipeline - Distributed Write-Ahead Log (WAL)
Uses Redis Streams to ensure durability of every state change across the mesh.
"""

from __future__ import annotations

import time
from typing import Any, cast

import redis

from src.core.logging.trace_logging import get_pipeline_logger

logger = get_pipeline_logger(__name__)


class FrontierWAL:
    """
    Append-only durability ledger for pipeline state transitions.
    Every 'merge_stage_output' is recorded here before mutation.
    """

    def __init__(self, redis_url: str | None, run_id: str) -> None:
        self._run_id = run_id
        self._stream_key = f"cyber:wal:{run_id}"
        if redis_url is None:
            logger.warning("Frontier WAL inactive: Redis URL is not configured")
            self._active = False
            return
        try:
            self._client = redis.from_url(redis_url, decode_responses=False)
            self._client.ping()
            self._active = True
        except Exception as exc:
            logger.warning("Frontier WAL inactive: Redis connection failed: %s", exc)
            self._active = False

    def log_delta(self, stage_name: str, delta: dict[str, Any]) -> str | None:
        """Record a state delta into the durable stream. Returns the entry ID."""
        if not self._active:
            return None

        try:
            import msgpack

            payload: dict[bytes, bytes] = {
                b"ts": str(time.time()).encode(),
                b"stage": stage_name.encode(),
                b"delta": cast(bytes, msgpack.packb(delta, use_bin_type=True)),
            }
            # Append to Redis Stream
            # Maxlen ensures we don't grow infinitely - increased to 10,000 per Audit #71
            entry_id = self._client.xadd(self._stream_key, cast(Any, payload), maxlen=10000)
            logger.debug("WAL recorded delta for '%s' (ID: %s)", stage_name, entry_id)
            return entry_id.decode() if isinstance(entry_id, bytes) else str(entry_id)
        except Exception as exc:
            logger.error("WAL append failed for stage '%s': %s", stage_name, exc)
            return None

    def recover_deltas(self, start_id: str | None = None) -> list[dict[str, Any]]:
        """
        Replay the WAL to reconstruct state after a crash.
        If start_id is provided, only deltas AFTER that ID are returned.
        """
        if not self._active:
            return []

        try:
            import msgpack

            deltas = []
            # Fix S1-2: Explicit None check to handle empty string start_id correctly
            cursor: str = f"({start_id}" if start_id is not None else "-"

            while True:
                raw_items = cast(
                    list[Any],
                    self._client.xrange(self._stream_key, min=cursor, max="+", count=1000),
                )
                if not raw_items:
                    break
                for item_id, item in raw_items:
                    deltas.append(
                        {
                            "id": item_id.decode() if isinstance(item_id, bytes) else str(item_id),
                            "stage": item[b"stage"].decode(),
                            "delta": msgpack.unpackb(item[b"delta"], raw=False),
                            "ts": float(item[b"ts"]),
                        }
                    )
                # Next cursor is exclusive '(' after the last seen ID
                last_id = raw_items[-1][0]
                last_id_str = last_id.decode() if isinstance(last_id, bytes) else str(last_id)
                cursor = f"({last_id_str}"

            return deltas
        except Exception as exc:
            logger.error("WAL recovery failed: %s", exc)
            return []

    def cleanup(self) -> None:
        """Purge the stream after successful scan completion."""
        if self._active:
            try:
                self._client.delete(self._stream_key)
            except Exception as exc:
                logger.warning("WAL cleanup failed for run %s: %s", self._run_id, exc)
