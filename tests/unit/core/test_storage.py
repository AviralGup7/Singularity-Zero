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

    path = store.write(run_id, 1, payload)
    assert os.path.exists(path)

    latest = store.read_latest(run_id)
    assert latest["status"] == "ok"

    versions = store.list_versions(run_id)
    assert len(versions) == 1

    store.delete(path)
    assert not os.path.exists(path)


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
