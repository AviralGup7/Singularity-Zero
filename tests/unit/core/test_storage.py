import os

import pytest

from src.core.storage.factory import (
    create_artifact_store,
    create_checkpoint_store,
    create_finding_store,
)
from src.core.storage.local_backends import (
    LocalArtifactStore,
    LocalCheckpointStore,
    LocalFindingStore,
)
from src.core.storage.redis_backends import RedisCheckpointStore


@pytest.fixture
def temp_storage(tmp_path):
    return tmp_path


def test_local_artifact_store(temp_storage):
    store = LocalArtifactStore(temp_storage)
    key = "test/file.txt"
    payload = b"hello world"

    path = store.put(key, payload)
    assert os.path.exists(path)
    assert store.get(key) == payload
    assert store.exists(key)

    files = store.list("test")
    assert "test/file.txt" in files

    store.delete(key)
    assert not store.exists(key)


def test_local_checkpoint_store(temp_storage):
    store = LocalCheckpointStore(temp_storage)
    run_id = "run123"
    payload = {"status": "ok", "completed_stages": ["recon"]}

    version_id = store.write(run_id, 1, payload)
    assert version_id == "v1"

    latest = store.read_latest(run_id)
    assert latest["status"] == "ok"

    versions = store.list_version_ids(run_id)
    assert versions == ["v1"]

    store.write(run_id, 2, {**payload, "checkpoint_version": 2})
    versions = store.list_version_ids(run_id)
    assert versions == ["v1", "v2"]

    store.delete_version(run_id, "v1")
    assert store.read_version_by_id(run_id, "v1") is None
    assert store.read_version_by_id(run_id, "v2") is not None


def test_local_checkpoint_store_rejects_path_shaped_version_id(temp_storage):
    store = LocalCheckpointStore(temp_storage)
    store.write("run-x", 1, {"checkpoint_version": 1})

    with pytest.raises(ValueError):
        store.read_version_by_id("run-x", "../escape")

    with pytest.raises(ValueError):
        store.delete_version("run-x", "../../etc/passwd")


def test_local_checkpoint_store_context_and_deltas(temp_storage):
    store = LocalCheckpointStore(temp_storage)
    run_id = "run-ctx"

    store.write_context_snapshot(run_id, "subdomains", {"context": {"x": 1}})
    snap = store.read_context_snapshot(run_id, "subdomains")
    assert snap is not None and snap["context"] == {"x": 1}

    for seq in (1, 2, 3):
        store.write_stage_delta(run_id, "live_hosts", seq, {"sequence": seq})
    deltas = store.list_stage_deltas(run_id, "live_hosts")
    assert [d["sequence"] for d in deltas] == [1, 2, 3]


def test_local_checkpoint_store_rejects_path_traversal_stage_name(temp_storage):
    store = LocalCheckpointStore(temp_storage)
    with pytest.raises(ValueError):
        store.write_context_snapshot("run", "../escape", {})
    with pytest.raises(ValueError):
        store.write_stage_delta("run", "ok/../bad", 1, {})


def test_local_checkpoint_store_list_run_ids(temp_storage):
    store = LocalCheckpointStore(temp_storage)
    store.write("run-a", 1, {"checkpoint_version": 1})
    store.write("run-b", 1, {"checkpoint_version": 1})
    assert store.list_run_ids() == ["run-a", "run-b"]


def test_local_finding_store(temp_storage):
    store = LocalFindingStore(temp_storage)
    run_id = "run123"
    findings = [{"id": 1, "category": "xss"}]

    store.save_many(run_id, findings)
    loaded = store.load_many(run_id)
    assert len(loaded) == 1
    assert loaded[0]["category"] == "xss"


def test_factory_local(temp_storage):
    config = {"backend": "local"}
    artifact_store = create_artifact_store(config, temp_storage)
    assert isinstance(artifact_store, LocalArtifactStore)

    checkpoint_store = create_checkpoint_store(config, temp_storage)
    assert isinstance(checkpoint_store, LocalCheckpointStore)

    finding_store = create_finding_store(config, temp_storage)
    assert isinstance(finding_store, LocalFindingStore)


def test_factory_redis_dispatch(tmp_path, monkeypatch):
    config = {"backend": "redis", "redis_url": "redis://localhost:6379/0"}
    fake_redis = _FakeRedis()
    monkeypatch.setattr(
        "redis.from_url",
        lambda *_args, **_kwargs: fake_redis,
    )
    store = create_checkpoint_store(config, tmp_path)
    assert isinstance(store, RedisCheckpointStore)

    version_id = store.write("run-redis", 1, {"checkpoint_version": 1})
    assert version_id == "v1"
    assert store.read_latest("run-redis") == {"checkpoint_version": 1}
    assert store.list_version_ids("run-redis") == ["v1"]


class _FakeRedis:
    """Tiny in-memory Redis stub sufficient for the RedisCheckpointStore."""

    def __init__(self) -> None:
        self._store: dict[str, bytes] = {}
        self._lists: dict[str, list[bytes]] = {}

    def ping(self) -> bool:
        return True

    def get(self, key):
        return self._store.get(key)

    def set(self, key, value):
        self._store[key] = value

    def delete(self, *keys):
        for k in keys:
            self._store.pop(k, None)

    def lrange(self, key, start, end):
        values = self._lists.get(key, [])
        if end == -1:
            return list(values[start:])
        return list(values[start : end + 1])

    def rpush(self, key, value):
        self._lists.setdefault(key, []).append(value)

    def lrem(self, key, count, value):
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

    def pipeline(self, transaction: bool = True):  # noqa: ARG002
        outer = self

        class _Pipe:
            def __init__(self) -> None:
                self.ops: list[tuple[str, tuple, dict]] = []

            def rpush(self, key, value):
                self.ops.append(("rpush", (key, value), {}))
                return self

            def set(self, key, value):
                self.ops.append(("set", (key, value), {}))
                return self

            def lrem(self, key, count, value):
                self.ops.append(("lrem", (key, count, value), {}))
                return self

            def delete(self, key):
                self.ops.append(("delete", (key,), {}))
                return self

            def execute(self):
                results = []
                for name, args, kwargs in self.ops:
                    method = getattr(outer, name)
                    results.append(method(*args, **kwargs))
                return results

        return _Pipe()

    def scan_iter(self, match: str = "*", count: int = 100):  # noqa: ARG002
        prefix = match.rstrip("*")
        for key in self._store:
            if isinstance(key, bytes) and key.decode("utf-8").startswith(prefix):
                yield key
