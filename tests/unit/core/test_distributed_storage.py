"""Tests for the distributed CheckpointStore slice.

Covers:
- ``RedisCheckpointStore`` roundtrip behaviour (using an in-memory fake client).
- ``CheckpointManager`` no longer leaks the local filesystem for context
  snapshots or stage deltas.
- ``attempt_recovery`` picks the best run across all backends.
- Env-var backfill for ``config.storage`` (``PIPELINE_STORAGE_*``).
- ``FrontierWAL`` honours ``aof_dir`` and no longer writes under the
  CWD-relative ``.pipeline/wal/`` when the orchestrator passes the run
  output dir.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest


class _FakeRedis:
    """Tiny in-memory Redis stub covering the surface RedisCheckpointStore uses."""

    def __init__(self) -> None:
        self._store: dict[str, bytes] = {}
        self._lists: dict[str, list[bytes]] = {}

    def ping(self) -> bool:
        return True

    def get(self, key: str) -> bytes | None:
        return self._store.get(key)

    def set(self, key: str, value: bytes) -> None:
        self._store[key] = value

    def delete(self, *keys: str) -> None:
        for k in keys:
            self._store.pop(k, None)

    def lrange(self, key: str, start: int, end: int) -> list[bytes]:
        values = self._lists.get(key, [])
        if end == -1:
            return list(values[start:])
        return list(values[start : end + 1])

    def rpush(self, key: str, value: bytes) -> None:
        self._lists.setdefault(key, []).append(value)

    def lrem(self, key: str, count: int, value: bytes) -> None:
        bucket = self._lists.get(key, [])
        if count == 0:
            self._lists[key] = [v for v in bucket if v != value]
        else:
            removed = 0
            new_bucket: list[bytes] = []
            for v in bucket:
                if v == value and (count < 0 or removed < count):
                    removed += 1
                    continue
                new_bucket.append(v)
            self._lists[key] = new_bucket

    def pipeline(self, transaction: bool = True) -> "_FakePipeline":  # noqa: ARG002
        return _FakePipeline(self)

    def scan_iter(self, match: str = "*", count: int = 100) -> Any:  # noqa: ARG002
        import fnmatch

        for key in list(self._store):
            decoded = key.decode("utf-8") if isinstance(key, bytes) else str(key)
            if fnmatch.fnmatchcase(decoded, match):
                yield key


class _FakePipeline:
    def __init__(self, redis_client: _FakeRedis) -> None:
        self._client = redis_client
        self._ops: list[tuple[str, tuple[Any, ...]]] = []

    def rpush(self, key: str, value: bytes) -> "_FakePipeline":
        self._ops.append(("rpush", (key, value)))
        return self

    def set(self, key: str, value: bytes) -> "_FakePipeline":
        self._ops.append(("set", (key, value)))
        return self

    def lrem(self, key: str, count: int, value: bytes) -> "_FakePipeline":
        self._ops.append(("lrem", (key, count, value)))
        return self

    def delete(self, key: str) -> "_FakePipeline":
        self._ops.append(("delete", (key,)))
        return self

    def execute(self) -> list[Any]:
        results = []
        for name, args in self._ops:
            results.append(getattr(self._client, name)(*args))
        return results


def _make_redis_store(redis_client: _FakeRedis):
    """Construct a ``RedisCheckpointStore`` without going through ``redis.from_url``."""
    from src.core.storage.redis_backends import RedisCheckpointStore

    store = RedisCheckpointStore.__new__(RedisCheckpointStore)
    store._client = redis_client
    store._prefix = "cyber:cp"
    return store


def test_redis_checkpoint_store_roundtrip() -> None:
    store = _make_redis_store(_FakeRedis())

    version_id = store.write("run-r", 1, {"checkpoint_version": 1, "x": 1})
    assert version_id == "v1"

    assert store.read_latest("run-r") == {"checkpoint_version": 1, "x": 1}
    assert store.read_version_by_id("run-r", "v1") == {"checkpoint_version": 1, "x": 1}
    assert store.list_version_ids("run-r") == ["v1"]

    store.write("run-r", 2, {"checkpoint_version": 2, "x": 9})
    assert store.list_version_ids("run-r") == ["v1", "v2"]
    assert store.read_latest("run-r")["x"] == 9


def test_redis_checkpoint_store_context_snapshot() -> None:
    store = _make_redis_store(_FakeRedis())

    store.write_context_snapshot("run-r", "subdomains", {"context": {"a": 1}})
    assert store.read_context_snapshot("run-r", "subdomains") == {"context": {"a": 1}}

    store.write_context_snapshot("run-r", "subdomains", {"context": {"a": 2}})
    assert store.read_context_snapshot("run-r", "subdomains") == {"context": {"a": 2}}


def test_redis_checkpoint_store_stage_deltas() -> None:
    store = _make_redis_store(_FakeRedis())

    for seq in (1, 2, 3):
        store.write_stage_delta("run-r", "live_hosts", seq, {"sequence": seq, "n": seq})

    deltas = store.list_stage_deltas("run-r", "live_hosts")
    assert [d["sequence"] for d in deltas] == [1, 2, 3]


def test_redis_checkpoint_store_list_run_ids() -> None:
    store = _make_redis_store(_FakeRedis())

    store.write("run-a", 1, {"checkpoint_version": 1})
    store.write("run-b", 1, {"checkpoint_version": 1})
    assert store.list_run_ids() == ["run-a", "run-b"]


def test_redis_checkpoint_store_delete_version() -> None:
    store = _make_redis_store(_FakeRedis())

    store.write("run-r", 1, {"checkpoint_version": 1})
    store.write("run-r", 2, {"checkpoint_version": 2})
    store.delete_version("run-r", "v1")
    assert store.read_version_by_id("run-r", "v1") is None
    assert store.read_version_by_id("run-r", "v2") == {"checkpoint_version": 2}
    assert store.list_version_ids("run-r") == ["v2"]


def test_checkpoint_manager_writes_context_snapshot_via_store(
    tmp_path: Path,
) -> None:
    """Path-leak fix: context snapshots must be written through the store."""
    from src.core.checkpoint.strategies import CheckpointManager
    from src.core.storage.local_backends import LocalCheckpointStore

    store = LocalCheckpointStore(tmp_path)
    manager = CheckpointManager(tmp_path / "checkpoints", "run-r", checkpoint_store=store)

    snapshot = {"scope_entries": ["a.com"], "stage_status": {"subdomains": "COMPLETED"}}
    manager.save_context_snapshot("subdomains", snapshot)

    stored = store.read_context_snapshot("run-r", "subdomains")
    assert stored is not None
    assert stored["context"] == snapshot

    loaded = manager.load_latest_context_snapshot(["subdomains"])
    assert loaded == snapshot


def test_checkpoint_manager_writes_stage_deltas_via_store(
    tmp_path: Path,
) -> None:
    """Path-leak fix: stage deltas must be written through the store."""
    from src.core.checkpoint.strategies import CheckpointManager
    from src.core.storage.local_backends import LocalCheckpointStore

    store = LocalCheckpointStore(tmp_path)
    manager = CheckpointManager(tmp_path / "checkpoints", "run-r", checkpoint_store=store)

    manager.save_stage_delta("live_hosts", {"context_delta": {"x": 1}})
    manager.save_stage_delta("live_hosts", {"context_delta": {"x": 2}})

    deltas = manager.load_stage_deltas("live_hosts")
    assert len(deltas) == 2
    assert [d["sequence"] for d in deltas] == [1, 2]


def test_attempt_recovery_picks_best_run(tmp_path: Path) -> None:
    """``attempt_recovery`` picks the run with the most completed stages."""
    from src.core.checkpoint.recovery import attempt_recovery
    from src.core.checkpoint.strategies import create_checkpoint_manager

    output_dir = tmp_path / "output"
    target = "demo"

    mgr_a = create_checkpoint_manager(output_dir, target, "run-a")
    mgr_a.mark_stage_complete("subdomains", {})

    mgr_b = create_checkpoint_manager(output_dir, target, "run-b")
    mgr_b.mark_stage_complete("subdomains", {})
    mgr_b.mark_stage_complete("live_hosts", {})

    can_recover, state = attempt_recovery(output_dir, target)
    assert can_recover is True
    assert state is not None
    assert state.pipeline_run_id == "run-b"


def test_storage_config_env_backfill_redis(monkeypatch: pytest.MonkeyPatch) -> None:
    from src.core.config import loader

    monkeypatch.setenv("PIPELINE_STORAGE_BACKEND", "redis")
    monkeypatch.setenv("PIPELINE_STORAGE_REDIS_URL", "redis://broker:6379/0")
    result = loader._resolve_storage_config({})
    assert result == {
        "backend": "redis",
        "redis_url": "redis://broker:6379/0",
    }

    monkeypatch.delenv("PIPELINE_STORAGE_BACKEND")
    monkeypatch.delenv("PIPELINE_STORAGE_REDIS_URL")
    result = loader._resolve_storage_config({})
    assert result == {"backend": "local"}


def test_storage_config_env_backfill_preserves_explicit_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from src.core.config import loader

    monkeypatch.setenv("PIPELINE_STORAGE_BACKEND", "redis")
    monkeypatch.setenv("PIPELINE_STORAGE_REDIS_URL", "redis://broker:6379/0")
    result = loader._resolve_storage_config(
        {"backend": "s3", "bucket": "explicit-bucket"}
    )
    assert result["backend"] == "s3"
    assert result["bucket"] == "explicit-bucket"
    assert result["redis_url"] == "redis://broker:6379/0"


def test_storage_config_env_backfill_s3(monkeypatch: pytest.MonkeyPatch) -> None:
    from src.core.config import loader

    monkeypatch.setenv("PIPELINE_STORAGE_BACKEND", "s3")
    monkeypatch.setenv("PIPELINE_STORAGE_S3_BUCKET", "my-bucket")
    monkeypatch.setenv("PIPELINE_STORAGE_S3_PREFIX", "checkpoints")
    monkeypatch.setenv("PIPELINE_STORAGE_S3_REGION", "us-east-1")

    result = loader._resolve_storage_config({})
    assert result == {
        "backend": "s3",
        "bucket": "my-bucket",
        "prefix": "checkpoints",
        "region_name": "us-east-1",
    }


def test_wal_aof_path_honours_aof_dir(tmp_path: Path) -> None:
    """FrontierWAL AOF must live under the declared aof_dir, not CWD."""
    from src.core.frontier.wal import FrontierWAL

    aof_dir = tmp_path / "run-output" / ".wal"
    wal = FrontierWAL(redis_url=None, run_id="run-aof", aof_dir=aof_dir)

    assert wal._aof_path.parent == aof_dir
    assert wal._aof_path.parent.exists()
    assert wal._aof_path.name.startswith("local_wal_run-aof")
    assert wal._aof_path.suffix == ".aof"

    wal.log_delta("stage_1", {"k": 1})
    assert wal._aof_path.exists()
    assert not (tmp_path / ".pipeline" / "wal" / f"local_wal_run-aof.aof").exists()

    recovered = wal.recover_deltas()
    assert len(recovered) == 1
    assert recovered[0]["stage"] == "stage_1"

    wal.cleanup()


def test_wal_default_aof_path_unchanged(tmp_path: Path, monkeypatch) -> None:
    """Backward-compat: callers that do not pass ``aof_dir`` still get
    ``.pipeline/wal/`` so existing tests keep working."""
    from src.core.frontier.wal import FrontierWAL

    monkeypatch.chdir(tmp_path)
    wal = FrontierWAL(redis_url=None, run_id="run-default")
    assert wal._aof_path.parent.resolve() == (tmp_path / ".pipeline" / "wal").resolve()
    wal.cleanup()
