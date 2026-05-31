from __future__ import annotations

import msgspec
import pytest

from src.core.frontier.bloom import NeuralBloomFilter
from src.core.frontier.bloom_mesh import (
    DEFAULT_SYNC_INTERVAL_SECONDS,
    NeuralBloomMesh,
)


def test_add_updates_element_count_once() -> None:
    bloom = NeuralBloomFilter(capacity=1000, error_rate=0.01)

    bloom.add("cache:key")
    bloom.add("cache:key")

    assert "cache:key" in bloom
    assert bloom.get_stats()["element_count"] == 1


def test_add_many_counts_unique_new_urls() -> None:
    bloom = NeuralBloomFilter(capacity=1000, error_rate=0.01)

    added = bloom.add_many(
        [
            " HTTPS://Example.test/a ",
            "https://example.test/a",
            "https://example.test/b",
            "ftp://example.test/ignored",
        ]
    )

    assert added == 2
    assert bloom.get_stats()["element_count"] == 2
    assert bloom.contains_many(["https://example.test/a", "https://example.test/b"]).tolist() == [
        True,
        True,
    ]


def test_process_urls_marks_repeated_urls_as_duplicates_within_batch() -> None:
    bloom = NeuralBloomFilter(capacity=1000, error_rate=0.01)

    result = bloom.process_urls(
        [
            "https://example.test/a",
            "https://example.test/a",
            "https://example.test/b",
        ],
        chunk_size=10,
    )

    assert result.added == 2
    assert result.known == 1
    assert result.duplicates.tolist() == [False, True, False]
    assert result.new_urls.tolist() == ["https://example.test/a", "https://example.test/b"]
    assert bloom.get_stats()["element_count"] == 2


@pytest.mark.asyncio
async def test_apply_snapshot_merges_without_replacing_local_bits() -> None:
    local = NeuralBloomFilter(capacity=1000, error_rate=0.01)
    local.add("https://local.test/only")
    local_mesh = NeuralBloomMesh(local, node_id="local")

    remote = NeuralBloomFilter(capacity=1000, error_rate=0.01)
    remote.add("https://remote.test/only")
    remote_mesh = NeuralBloomMesh(remote, node_id="remote")
    await remote_mesh.publish_snapshot()

    payload = remote_mesh._encode_snapshot(reason="test", timestamp=remote_mesh._last_sync_time)

    assert await local_mesh.apply_snapshot(payload) is True
    assert "https://local.test/only" in local
    assert "https://remote.test/only" in local
    assert local.get_stats()["element_count"] == 2


@pytest.mark.asyncio
async def test_apply_snapshot_rejects_malformed_payload_without_raising() -> None:
    bloom = NeuralBloomFilter(capacity=1000, error_rate=0.01)
    mesh = NeuralBloomMesh(bloom, node_id="local")

    assert await mesh.apply_snapshot(msgspec.msgpack.encode(["not", "a", "mapping"])) is False
    assert mesh.health_snapshot()["snapshot_apply_failures_total"] == 1


def test_invalid_sync_interval_env_falls_back(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BLOOM_SYNC_INTERVAL_SEC", "not-a-number")

    mesh = NeuralBloomMesh(NeuralBloomFilter(), node_id="local")

    assert mesh.sync_interval_seconds == DEFAULT_SYNC_INTERVAL_SECONDS


def test_invalid_constructor_values_raise() -> None:
    with pytest.raises(ValueError):
        NeuralBloomFilter(capacity=0)
    with pytest.raises(ValueError):
        NeuralBloomFilter(error_rate=1.0)
