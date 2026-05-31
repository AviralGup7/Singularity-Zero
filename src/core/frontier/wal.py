"""
Cyber Security Test Pipeline - Distributed Write-Ahead Log (WAL)
Uses Redis Streams to ensure durability of every state change across the mesh.
"""

from __future__ import annotations

import base64
import json
import os
import re
import threading
import time
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any, cast

import redis

from src.core.frontier.state import NeuralState, stable_digest
from src.core.logging.trace_logging import get_pipeline_logger

logger = get_pipeline_logger(__name__)


# CRC-64-ECMA polynomial: 0x42F0E1EBA9EA3693
POLY_64 = 0x42F0E1EBA9EA3693
CRC64_TABLE: list[int] = []
_CRC64_TABLE_LOCK = threading.Lock()
_AOF_LOCKS: dict[str, threading.Lock] = {}
_AOF_LOCKS_GUARD = threading.Lock()
_REDIS_STREAM_ID_RE = re.compile(r"^\d+-\d+$")
_AOF_RETENTION_SECONDS = 7 * 24 * 60 * 60
REDIS_TIMEOUT_SECONDS = 5
REDIS_RETRIES = 2
REDIS_BACKOFF_SECONDS = 0.1


def _init_crc64_table() -> None:
    if len(CRC64_TABLE) == 256:
        return
    with _CRC64_TABLE_LOCK:
        if len(CRC64_TABLE) == 256:
            return
        table: list[int] = []
        for i in range(256):
            crc = i
            for _ in range(8):
                if crc & 1:
                    crc = (crc >> 1) ^ POLY_64
                else:
                    crc >>= 1
            table.append(crc)
        CRC64_TABLE[:] = table


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


def _safe_run_filename(run_id: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", run_id).strip("._")
    safe = safe or "run"
    if safe != run_id or len(safe) > 120:
        digest = stable_digest(run_id)[:12]
        safe = f"{safe[:100]}-{digest}"
    return safe


def _aof_lock(path: Path) -> threading.Lock:
    lock_key = str(path.resolve(strict=False))
    with _AOF_LOCKS_GUARD:
        lock = _AOF_LOCKS.get(lock_key)
        if lock is None:
            lock = threading.Lock()
            _AOF_LOCKS[lock_key] = lock
        return lock


def _is_redis_stream_id(value: str | None) -> bool:
    return isinstance(value, str) and bool(_REDIS_STREAM_ID_RE.match(value))


def _stream_id_tuple(value: str) -> tuple[int, int] | None:
    if not _is_redis_stream_id(value):
        return None
    ms, seq = value.split("-", 1)
    return int(ms), int(seq)


def _decode_text(value: Any, default: str = "") -> str:
    if value is None:
        return default
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def _ensure_bytes(value: Any) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, str):
        return value.encode("utf-8")
    raise TypeError(f"Expected bytes-like WAL field, got {type(value).__name__}")


def _field(item: Mapping[Any, Any], name: str, default: Any = None) -> Any:
    byte_name = name.encode("utf-8")
    if byte_name in item:
        return item[byte_name]
    if name in item:
        return item[name]
    return default


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
        # Setup local append-only file (AOF) path for dual-commit in gitignored directory
        wal_dir = Path(".pipeline") / "wal"
        self._aof_path = wal_dir / f"local_wal_{_safe_run_filename(run_id)}.aof"
        try:
            wal_dir.mkdir(parents=True, exist_ok=True)
            self._prune_expired_aof_files(wal_dir)
        except Exception as e:
            logger.debug("Failed to initialize WAL directory or prune old logs: %s", e)

        if redis_url is None:
            logger.warning("Frontier WAL inactive: Redis URL is not configured")
            self._active = False
            return
        try:
            self._client = redis.from_url(
                redis_url,
                decode_responses=False,
                socket_connect_timeout=REDIS_TIMEOUT_SECONDS,
                socket_timeout=REDIS_TIMEOUT_SECONDS,
                health_check_interval=30,
                retry_on_timeout=True,
                max_connections=10,
            )
            self._redis_call(lambda: self._client.ping(), mark_inactive=False)
            self._active = True
        except (redis.exceptions.RedisError, ValueError, ConnectionError, Exception) as exc:
            logger.warning("Frontier WAL inactive: Redis connection failed: %s", exc)
            self._active = False

    def _prune_expired_aof_files(self, wal_dir: Path) -> None:
        """Remove stale local WAL files without deleting active/recent recovery anchors."""
        now = time.time()
        for wal_file in wal_dir.glob("local_wal_*.aof"):
            try:
                if wal_file.resolve(strict=False) == self._aof_path.resolve(strict=False):
                    continue
                if now - wal_file.stat().st_mtime > _AOF_RETENTION_SECONDS:
                    wal_file.unlink(missing_ok=True)
            except OSError as exc:
                logger.debug("Failed to prune stale WAL AOF %s: %s", wal_file, exc)

    def _append_aof_entry(
        self,
        *,
        event_ts: float,
        stage_name: str,
        wal_id: str,
        tx_id: str,
        crc64_hash: str,
        packed_delta: bytes,
        stream_id: str | None,
    ) -> bool:
        aof_entry = {
            "ts": event_ts,
            "stage": stage_name,
            "id": wal_id,
            "tx_id": tx_id,
            "crc64": crc64_hash,
            "delta": base64.b64encode(packed_delta).decode("utf-8"),
        }
        if stream_id:
            aof_entry["stream_id"] = stream_id

        try:
            lock = _aof_lock(self._aof_path)
            with lock:
                with open(self._aof_path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(aof_entry, separators=(",", ":")) + "\n")
                    f.flush()
                    try:
                        os.fsync(f.fileno())
                    except OSError as e:
                        logger.debug("WAL AOF fsync failed (might be virtual/mocked drive): %s", e)
            return True
        except (OSError, TypeError, ValueError, Exception) as exc:
            logger.error("WAL AOF append failed for stage '%s': %s", stage_name, exc)
            return False

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

            payload: dict[bytes, bytes] = {
                b"ts": str(event_ts).encode(),
                b"stage": stage_name.encode(),
                b"tx_id": tx_id.encode(),
                b"crc64": crc64_hash.encode(),
                b"delta": packed_delta,
            }

            stream_id: str | None = None
            if self._active:
                try:
                    entry_id = self._redis_call(
                        lambda: self._client.xadd(
                            self._stream_key,
                            cast(Any, payload),
                            maxlen=self._max_stream_entries,
                        )
                    )
                    stream_id = entry_id.decode() if isinstance(entry_id, bytes) else str(entry_id)
                except (redis.exceptions.RedisError, ValueError, TypeError, Exception) as exc:
                    self._active = False
                    logger.warning(
                        "WAL Redis append failed for stage '%s'; attempting AOF fallback: %s",
                        stage_name,
                        exc,
                    )

            wal_id = stream_id or f"aof-{event_ts:.9f}-{tx_id[:12]}"
            aof_ok = self._append_aof_entry(
                event_ts=event_ts,
                stage_name=stage_name,
                wal_id=wal_id,
                tx_id=tx_id,
                crc64_hash=crc64_hash,
                packed_delta=packed_delta,
                stream_id=stream_id,
            )

            if stream_id:
                logger.debug("WAL recorded delta for '%s' (ID: %s)", stage_name, stream_id)
                return stream_id
            if aof_ok:
                logger.debug("WAL recorded AOF-only delta for '%s' (ID: %s)", stage_name, wal_id)
                return wal_id
            logger.error(
                "WAL append failed for stage '%s': no durable backend accepted record",
                stage_name,
            )
            return None
        except (
            ValueError,
            TypeError,
            AttributeError,
            Exception,
        ) as exc:
            logger.error("WAL append failed for stage '%s': %s", stage_name, exc)
            return None

    def _read_redis_deltas(
        self, start_id: str | None, msgpack_module: Any
    ) -> tuple[list[dict[str, Any]], bool]:
        redis_deltas: list[dict[str, Any]] = []
        if not self._active:
            return redis_deltas, True

        try:
            start_id_norm = start_id.strip() if isinstance(start_id, str) else None
            cursor = f"({start_id_norm}" if _is_redis_stream_id(start_id_norm) else "-"

            while True:
                raw_items = cast(
                    list[Any],
                    self._redis_call(
                        lambda: self._client.xrange(
                            self._stream_key,
                            min=cursor,
                            max="+",
                            count=1000,
                        )
                    ),
                )
                if not raw_items:
                    break
                for item_id, item in raw_items:
                    if not isinstance(item, Mapping):
                        raise ValueError("Redis WAL entry fields are not a mapping")
                    wal_id = _decode_text(item_id)
                    raw_delta = _ensure_bytes(_field(item, "delta"))
                    stored_crc = _decode_text(_field(item, "crc64", b""))

                    computed_crc = compute_crc64(raw_delta)
                    if stored_crc and computed_crc != stored_crc:
                        logger.error(
                            "WAL Redis stream corruption detected at ID %s! CRC mismatch",
                            wal_id,
                        )
                        return [], True

                    tx_id = _decode_text(_field(item, "tx_id", b""))
                    redis_deltas.append(
                        {
                            "id": wal_id,
                            "stream_id": wal_id,
                            "stage": _decode_text(_field(item, "stage")),
                            "delta": msgpack_module.unpackb(raw_delta, raw=False),
                            "ts": float(_decode_text(_field(item, "ts", b"0"))),
                            "tx_id": tx_id,
                            "_source": "redis",
                        }
                    )
                last_id = raw_items[-1][0]
                cursor = f"({_decode_text(last_id)}"
        except (redis.exceptions.RedisError, Exception) as exc:
            logger.error("WAL Redis xrange recovery failed, falling back to AOF: %s", exc)
            return [], True

        return redis_deltas, False

    def _read_aof_deltas(self, msgpack_module: Any) -> list[dict[str, Any]]:
        if not self._aof_path.exists():
            return []

        logger.info("WAL recovering from local AOF replica: %s", self._aof_path)
        aof_deltas: list[dict[str, Any]] = []
        try:
            with open(self._aof_path, encoding="utf-8") as f:
                for line in f:
                    if not line.strip():
                        continue
                    try:
                        entry = json.loads(line)
                        raw_delta = base64.b64decode(entry["delta"], validate=True)
                        stored_crc = entry.get("crc64")

                        computed_crc = compute_crc64(raw_delta)
                        if stored_crc and computed_crc != stored_crc:
                            logger.error(
                                "WAL AOF file corruption detected for stage %s (tx_id: %s)! Skipping entry.",
                                entry.get("stage"),
                                entry.get("tx_id"),
                            )
                            continue

                        stream_id = entry.get("stream_id")
                        wal_id = (
                            entry.get("id")
                            or stream_id
                            or entry.get("tx_id")
                            or f"aof-{entry['ts']}"
                        )
                        aof_deltas.append(
                            {
                                "id": str(wal_id),
                                "stream_id": str(stream_id) if stream_id else None,
                                "stage": str(entry["stage"]),
                                "delta": msgpack_module.unpackb(raw_delta, raw=False),
                                "ts": float(entry["ts"]),
                                "tx_id": str(entry.get("tx_id") or ""),
                                "_source": "aof",
                            }
                        )
                    except (json.JSONDecodeError, ValueError, KeyError, Exception) as exc:
                        logger.error("WAL AOF entry parse failed: %s", exc)
        except (OSError, Exception) as exc:
            logger.error("WAL AOF recovery failed completely: %s", exc)
            return []

        return aof_deltas

    def _filter_after_start(
        self, entries: list[dict[str, Any]], start_id: str | None
    ) -> list[dict[str, Any]]:
        start_id_norm = start_id.strip() if isinstance(start_id, str) else None
        if not start_id_norm:
            return entries

        for index, entry in enumerate(entries):
            if start_id_norm in {
                str(entry.get("id") or ""),
                str(entry.get("stream_id") or ""),
                str(entry.get("tx_id") or ""),
            }:
                return entries[index + 1 :]

        start_tuple = _stream_id_tuple(start_id_norm)
        if start_tuple is None:
            return entries

        filtered = []
        for entry in entries:
            entry_stream_id = entry.get("stream_id") or entry.get("id")
            entry_tuple = _stream_id_tuple(str(entry_stream_id))
            if entry_tuple is not None and entry_tuple > start_tuple:
                filtered.append(entry)
        return filtered

    def _merge_recovered_deltas(
        self, redis_deltas: list[dict[str, Any]], aof_deltas: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        merged: dict[str, dict[str, Any]] = {}
        sequence: dict[str, int] = {}

        for entry in [*aof_deltas, *redis_deltas]:
            dedupe_key = str(entry.get("tx_id") or entry.get("stream_id") or entry.get("id"))
            existing = merged.get(dedupe_key)
            if existing is None:
                sequence[dedupe_key] = len(sequence)
                merged[dedupe_key] = entry
                continue
            if existing.get("_source") == "aof" and entry.get("_source") == "redis":
                merged[dedupe_key] = entry

        def sort_key(entry: dict[str, Any]) -> tuple[float, int, int, int]:
            stream_id = entry.get("stream_id") or entry.get("id")
            stream_tuple = _stream_id_tuple(str(stream_id))
            dedupe_key = str(entry.get("tx_id") or entry.get("stream_id") or entry.get("id"))
            if stream_tuple is None:
                stream_tuple = (0, sequence.get(dedupe_key, 0))
            return (
                float(entry.get("ts") or 0.0),
                stream_tuple[0],
                stream_tuple[1],
                sequence.get(dedupe_key, 0),
            )

        recovered = sorted(merged.values(), key=sort_key)
        for entry in recovered:
            entry.pop("_source", None)
        return recovered

    def recover_deltas(self, start_id: str | None = None) -> list[dict[str, Any]]:
        """
        Replay the WAL to reconstruct state after a crash.
        Supports rolling integrity checks via CRC64. If Redis is down or entry is corrupted,
        falls back to local AOF replica, and vice versa.
        """
        import msgpack

        redis_deltas, redis_failed = self._read_redis_deltas(start_id, msgpack)
        aof_deltas = self._read_aof_deltas(msgpack)

        if redis_failed:
            return self._filter_after_start(aof_deltas, start_id)

        recovered = self._merge_recovered_deltas(redis_deltas, aof_deltas)
        return self._filter_after_start(recovered, start_id)

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
                self._redis_call(lambda: self._client.set(self._snapshot_key, payload))
                if hasattr(self._client, "expire"):
                    self._redis_call(lambda: self._client.expire(self._snapshot_key, 86400))
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

            payload = self._redis_call(lambda: self._client.get(self._snapshot_key))
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
            self._redis_call(
                lambda: self._client.xtrim(
                    self._stream_key,
                    maxlen=max(keep_entries, 1),
                    approximate=True,
                )
            )
            return True
        except (redis.exceptions.RedisError, Exception) as exc:
            logger.warning("WAL stream compaction failed for run %s: %s", self._run_id, exc)
            return False

    def cleanup(self) -> None:
        """Purge the stream and AOF after successful scan completion."""
        if self._active:
            try:
                if hasattr(self._client, "delete"):
                    self._redis_call(lambda: self._client.delete(self._stream_key))
                    self._redis_call(lambda: self._client.delete(self._snapshot_key))
            except (redis.exceptions.RedisError, Exception) as exc:
                logger.warning("WAL cleanup failed for run %s: %s", self._run_id, exc)
        # Delete local AOF
        try:
            if self._aof_path.exists():
                self._aof_path.unlink()
        except (OSError, Exception) as exc:
            logger.warning("WAL AOF cleanup failed: %s", exc)

    def close(self) -> None:
        """Close Redis resources held by the WAL."""
        client = getattr(self, "_client", None)
        if client is None:
            return
        try:
            client.close()
        except Exception as exc:
            logger.debug("WAL Redis close failed for run %s: %s", self._run_id, exc)
        finally:
            self._active = False

    def _redis_call(self, fn: Callable[[], Any], *, mark_inactive: bool = True) -> Any:
        delay = REDIS_BACKOFF_SECONDS
        last_error: Exception | None = None
        for attempt in range(REDIS_RETRIES + 1):
            try:
                return fn()
            except Exception as exc:
                last_error = exc
                if attempt >= REDIS_RETRIES:
                    break
                time.sleep(delay)
                delay *= 2
        if mark_inactive:
            self._active = False
        raise last_error or RuntimeError("Redis WAL operation failed")
