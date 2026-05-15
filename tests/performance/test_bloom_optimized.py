"""Performance guardrails for the optimized Bloom frontier.

The full 10M URL path is gated behind BLOOM_PERF_FULL=1 so routine test runs stay
offline and bounded.
"""

from __future__ import annotations

import asyncio
import os
import random
import string
import time

import pytest

from src.core.frontier.bloom import NeuralBloomFilter
from src.core.frontier.bloom_mesh import BloomMeshSynchronizer
from src.core.frontier.ghost_vfs import GhostVFS

try:
    import psutil
except ImportError:  # pragma: no cover
    psutil = None


pytestmark = pytest.mark.benchmark


def _urls(count: int, prefix: str = "member") -> list[str]:
    return [f"https://example.test/{prefix}/{idx:08d}?q={idx % 97}" for idx in range(count)]


def _random_strings(count: int, prefix: str) -> list[str]:
    alphabet = string.ascii_lowercase + string.digits
    rng = random.Random(1337)
    return [
        f"https://fp.example/{prefix}/" + "".join(rng.choice(alphabet) for _ in range(24))
        for _ in range(count)
    ]


def test_process_urls_vectorized_smoke_throughput() -> None:
    bloom = NeuralBloomFilter(capacity=250_000, error_rate=0.001)
    urls = _urls(100_000)

    started = time.perf_counter()
    first = bloom.process_urls(urls, chunk_size=100_000)
    elapsed = time.perf_counter() - started
    second = bloom.process_urls(urls, add_missing=False, chunk_size=100_000)

    assert first.added == 100_000
    assert second.known == 100_000
    assert first.chunk_size == 100_000
    assert elapsed > 0


def test_false_positive_rate_small_offline_guardrail() -> None:
    bloom = NeuralBloomFilter(capacity=150_000, error_rate=0.001)
    bloom.add_many(_random_strings(100_000, "in"))

    non_members = _random_strings(25_000, "out")
    positives = bloom.contains_many(non_members)
    fp_rate = positives.sum() / len(non_members)

    assert fp_rate < 0.001


def test_bloom_snapshot_sync_latency_without_redis() -> None:
    source = BloomMeshSynchronizer(
        NeuralBloomFilter(capacity=10_000, error_rate=0.001),
        node_id="node-a",
    )
    target = BloomMeshSynchronizer(
        NeuralBloomFilter(capacity=10_000, error_rate=0.001),
        node_id="node-b",
    )
    source.filter.add_many(_urls(2_000))
    source.clock = source.clock.increment("node-a")

    started = time.perf_counter()
    payload = source._encode_snapshot(reason="test", timestamp=time.time())
    applied = asyncio.run(async_apply(target, payload))
    latency = time.perf_counter() - started

    assert applied is True
    assert "https://example.test/member/00000042?q=42" in target.filter
    assert latency < 0.5


async def async_apply(target: BloomMeshSynchronizer, payload: bytes) -> bool:
    return await target.apply_snapshot(payload)


def test_ghost_vfs_rss_smoke() -> None:
    before = psutil.Process().memory_info().rss if psutil else 0
    vfs = GhostVFS()
    bloom = NeuralBloomFilter(capacity=100_000, error_rate=0.001)
    bloom.add_many(_urls(20_000, "ghost"))
    vfs.write_file("bloom.snapshot", bloom.snapshot_bytes())
    after = psutil.Process().memory_info().rss if psutil else before

    assert vfs.read_file("bloom.snapshot")
    assert after - before < 256 * 1024 * 1024


@pytest.mark.skipif(os.getenv("BLOOM_PERF_FULL") != "1", reason="Set BLOOM_PERF_FULL=1 for 10M benchmark")
@pytest.mark.parametrize("batch_size", [100_000, 1_000_000, 10_000_000])
def test_full_scale_single_node_throughput(batch_size: int) -> None:
    bloom = NeuralBloomFilter(capacity=10_000_000, error_rate=0.001)
    urls = _urls(batch_size)
    started = time.perf_counter()
    result = bloom.process_urls(urls)
    elapsed = time.perf_counter() - started

    assert result.added == batch_size
    assert batch_size / elapsed > 0


@pytest.mark.skipif(os.getenv("BLOOM_PERF_FULL") != "1", reason="Set BLOOM_PERF_FULL=1 for 10M FP benchmark")
def test_full_scale_false_positive_rate() -> None:
    bloom = NeuralBloomFilter(capacity=10_000_000, error_rate=0.001)
    bloom.add_many(_random_strings(10_000_000, "in"))

    non_members = _random_strings(100_000, "out")
    positives = bloom.contains_many(non_members)
    fp_rate = positives.sum() / len(non_members)

    assert fp_rate < 0.001
