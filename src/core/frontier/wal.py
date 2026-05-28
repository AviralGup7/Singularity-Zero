"""
Cyber Security Test Pipeline - Distributed Write-Ahead Log (WAL)
Uses Redis Streams to ensure durability of every state change across the mesh.
"""

from __future__ import annotations

import base64
import json
import time
from pathlib import Path
from typing import Any, cast

import redis

from src.core.frontier.state import NeuralState, stable_digest
from src.core.logging.trace_logging import get_pipeline_logger

logger = get_pipeline_logger(__name__)


# CRC-64-ECMA polynomial: 0x42F0E1EBA9EA3693
POLY_64 = 0x42F0E1EBA9EA3693
CRC64_TABLE: list[int] = []


def _init_crc64_table() -> None:
    if CRC64_TABLE:
        return
    for i in range(256):
        crc = i
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ POLY_64
            else:
                crc >>= 1
        CRC64_TABLE.append(crc)


def crc64_pure(data: bytes) -> int:
    _init_crc64_table()
    crc = 0xFFFFFFFFFFFFFFFF
    for b in data:
        crc = CRC64_TABLE[(crc ^ b) & 0xFF] ^ (crc >> 8)
    return crc ^ 0xFFFFFFFFFFFFFFFF


try:
    import crcmod

    _crc64_func = crcmod.mkCrcFun(
        POLY_64, rev=True, initCrc=0xFFFFFFFFFFFFFFFF, xorOut=0xFFFFFFFFFFFFFFFF
    )

    def compute_crc64(data: bytes) -> str:
        return f"{_crc64_func(data):016x}"
except (ImportError, ValueError):

    def compute_crc64(data: bytes) -> str:
        return f"{crc64_pure(data):016x}"


class FrontierWAL:
    """
    Append-only durability ledger for pipeline state transitions.
    Every 'merge_stage_output' is recorded here before mutation.
    """

    def __init__(self, redis_url: str | None, run_id: str) -> None:
        self._run_id = run_id
        self._stream_key = f"cyber:wal:{run_id}"
        self._snapshot_key = f"cyber:wal:snapshot:{run_id}"
        self._max_stream_entries = 10000
        # Setup local append-only file (AOF) path for dual-commit
        self._aof_path = Path(f"./local_wal_{run_id}.aof")

        if redis_url is None:
            logger.warning("Frontier WAL inactive: Redis URL is not configured")
            self._active = False
            return
        try:
            self._client = redis.from_url(redis_url, decode_responses=False)
            self._client.ping()
            self._active = True
        except (redis.exceptions.RedisError, ValueError, ConnectionError, Exception) as exc:
            logger.warning("Frontier WAL inactive: Redis connection failed: %s", exc)
            self._active = False

    def log_delta(self, stage_name: str, delta: dict[str, Any]) -> str | None:
        """Record a state delta into the durable stream (Redis) and local AOF (dual-commit)."""
        try:
            import msgpack

            event_ts = time.time()
            tx_id = stable_digest(
                {
                    "run_id": self._run_id,
                    "stage": stage_name,
                    "delta": delta,
                    "ts": delta.get("_ts", event_ts),
                }
            )

            packed_delta = cast(bytes, msgpack.packb(delta, use_bin_type=True))
            crc64_hash = compute_crc64(packed_delta)

            # 1. Dual Commit: Write to local AOF
            try:
                aof_entry = {
                    "ts": event_ts,
                    "stage": stage_name,
                    "tx_id": tx_id,
                    "crc64": crc64_hash,
                    "delta": base64.b64encode(packed_delta).decode("utf-8"),
                }
                with open(self._aof_path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(aof_entry) + "\n")
                    f.flush()
                    import os

                    try:
                        os.fsync(f.fileno())
                    except OSError as e:
                        logger.debug("WAL AOF fsync failed (might be virtual/mocked drive): %s", e)
            except (OSError, TypeError, ValueError, Exception) as exc:
                logger.error("WAL AOF append failed for stage '%s': %s", stage_name, exc)

            # 2. Dual Commit: Write to Redis Stream
            if not self._active:
                return f"aof-{event_ts}"

            payload: dict[bytes, bytes] = {
                b"ts": str(event_ts).encode(),
                b"stage": stage_name.encode(),
                b"tx_id": tx_id.encode(),
                b"crc64": crc64_hash.encode(),
                b"delta": packed_delta,
            }
            # Append to Redis Stream
            entry_id = self._client.xadd(
                self._stream_key,
                cast(Any, payload),
                maxlen=self._max_stream_entries,
            )
            logger.debug("WAL recorded delta for '%s' (ID: %s)", stage_name, entry_id)
            return entry_id.decode() if isinstance(entry_id, bytes) else str(entry_id)
        except (redis.exceptions.RedisError, ValueError, TypeError, AttributeError, Exception) as exc:
            logger.error("WAL append failed for stage '%s': %s", stage_name, exc)
            return None

    def recover_deltas(self, start_id: str | None = None) -> list[dict[str, Any]]:
        """
        Replay the WAL to reconstruct state after a crash.
        Supports rolling integrity checks via CRC64. If Redis is down or entry is corrupted,
        falls back to local AOF replica, and vice versa.
        """
        import msgpack

        # Try Redis first
        redis_deltas = []
        redis_failed = not self._active
        if self._active:
            try:
                start_id_norm = start_id.strip() if isinstance(start_id, str) else None
                cursor: str = f"({start_id_norm}" if start_id_norm else "-"

                while True:
                    raw_items = cast(
                        list[Any],
                        self._client.xrange(self._stream_key, min=cursor, max="+", count=1000),
                    )
                    if not raw_items:
                        break
                    for item_id, item in raw_items:
                        wal_id = item_id.decode() if isinstance(item_id, bytes) else str(item_id)
                        raw_delta = item[b"delta"]
                        stored_crc = item.get(b"crc64", b"").decode()

                        # Validate integrity
                        computed_crc = compute_crc64(raw_delta)
                        if stored_crc and computed_crc != stored_crc:
                            logger.error(
                                "WAL Redis stream corruption detected at ID %s! CRC mismatch",
                                wal_id,
                            )
                            redis_failed = True
                            break

                        redis_deltas.append(
                            {
                                "id": wal_id,
                                "stage": item[b"stage"].decode(),
                                "delta": msgpack.unpackb(raw_delta, raw=False),
                                "ts": float(item[b"ts"]),
                                "tx_id": (
                                    item.get(b"tx_id", b"").decode() if hasattr(item, "get") else ""
                                ),
                            }
                        )
                    if redis_failed:
                        break
                    last_id = raw_items[-1][0]
                    last_id_str = last_id.decode() if isinstance(last_id, bytes) else str(last_id)
                    cursor = f"({last_id_str}"
            except (redis.exceptions.RedisError, Exception) as exc:
                logger.error("WAL Redis xrange recovery failed, falling back to AOF: %s", exc)
                redis_failed = True

        if not redis_failed:
            return redis_deltas

        # Fallback to local AOF replica
        logger.info("WAL recovering from local AOF replica: %s", self._aof_path)
        if not self._aof_path.exists():
            return []

        aof_deltas = []
        try:
            with open(self._aof_path, encoding="utf-8") as f:
                for line in f:
                    if not line.strip():
                        continue
                    try:
                        entry = json.loads(line)
                        raw_delta = base64.b64decode(entry["delta"])
                        stored_crc = entry.get("crc64")

                        # Validate integrity
                        computed_crc = compute_crc64(raw_delta)
                        if stored_crc and computed_crc != stored_crc:
                            logger.error(
                                "WAL AOF file corruption detected for stage %s (tx_id: %s)! Skipping entry.",
                                entry["stage"],
                                entry["tx_id"],
                            )
                            continue

                        aof_deltas.append(
                            {
                                "id": entry.get("tx_id") or f"aof-{entry['ts']}",
                                "stage": entry["stage"],
                                "delta": msgpack.unpackb(raw_delta, raw=False),
                                "ts": entry["ts"],
                                "tx_id": entry["tx_id"],
                            }
                        )
                    except (json.JSONDecodeError, ValueError, KeyError, Exception) as exc:
                        logger.error("WAL AOF entry parse failed: %s", exc)
        except (OSError, Exception) as exc:
            logger.error("WAL AOF recovery failed completely: %s", exc)
            return []

        # Return AOF deltas
        return aof_deltas

    def persist_snapshot(self, state: NeuralState, *, reason: str = "checkpoint") -> bool:
        """Persist the latest full CRDT snapshot used as the cold-start anchor."""
        if not self._active:
            return False

        try:
            import msgpack

            envelope = {
                "run_id": self._run_id,
                "reason": reason,
                "snapshot": state.to_crdt_snapshot(),
            }
            envelope["digest"] = stable_digest(envelope["snapshot"])
            payload = cast(bytes, msgpack.packb(envelope, use_bin_type=True))
            if hasattr(self._client, "set"):
                self._client.set(self._snapshot_key, payload)
                if hasattr(self._client, "expire"):
                    self._client.expire(self._snapshot_key, 86400)
                logger.info(
                    "WAL persisted CRDT snapshot for run %s at cursor %s",
                    self._run_id,
                    state.last_wal_id,
                )
                return True
        except (redis.exceptions.RedisError, ValueError, Exception) as exc:
            logger.error("WAL snapshot persist failed for run %s: %s", self._run_id, exc)
        return False

    def load_snapshot(self) -> dict[str, Any] | None:
        """Load the latest durable snapshot envelope, if one exists."""
        if not self._active or not hasattr(self._client, "get"):
            return None

        try:
            import msgpack

            payload = self._client.get(self._snapshot_key)
            if not payload:
                return None
            envelope = msgpack.unpackb(payload, raw=False)
            if not isinstance(envelope, dict):
                return None
            snapshot = envelope.get("snapshot")
            expected = envelope.get("digest")
            if expected and stable_digest(snapshot) != expected:
                logger.error("WAL snapshot digest mismatch for run %s", self._run_id)
                return None
            return cast(dict[str, Any], envelope)
        except (redis.exceptions.RedisError, ValueError, Exception) as exc:
            logger.error("WAL snapshot load failed for run %s: %s", self._run_id, exc)
            return None

    def recover_state(self) -> NeuralState:
        """Rebuild NeuralState from the latest snapshot plus post-snapshot WAL entries."""
        envelope = self.load_snapshot()
        snapshot = envelope.get("snapshot") if isinstance(envelope, dict) else None
        state = NeuralState.from_crdt_snapshot(snapshot if isinstance(snapshot, dict) else None)
        for entry in self.recover_deltas(state.last_wal_id):
            delta = entry.get("delta")
            if isinstance(delta, dict):
                delta.setdefault("_wal_id", entry.get("id"))
                state.apply_delta(delta)
        return state

    def compact_after_snapshot(self, state: NeuralState, *, keep_entries: int = 1000) -> bool:
        """Persist a snapshot and trim older stream entries within the compaction budget."""
        if not self.persist_snapshot(state, reason="compaction"):
            return False
        if not self._active or not hasattr(self._client, "xtrim"):
            return True
        try:
            self._client.xtrim(self._stream_key, maxlen=max(keep_entries, 1), approximate=True)
            return True
        except (redis.exceptions.RedisError, Exception) as exc:
            logger.warning("WAL stream compaction failed for run %s: %s", self._run_id, exc)
            return False

    def cleanup(self) -> None:
        """Purge the stream and AOF after successful scan completion."""
        if self._active:
            try:
                if hasattr(self._client, "delete"):
                    self._client.delete(self._stream_key)
                    self._client.delete(self._snapshot_key)
            except (redis.exceptions.RedisError, Exception) as exc:
                logger.warning("WAL cleanup failed for run %s: %s", self._run_id, exc)
        # Delete local AOF
        try:
            if self._aof_path.exists():
                self._aof_path.unlink()
        except (OSError, Exception) as exc:
            logger.warning("WAL AOF cleanup failed: %s", exc)
