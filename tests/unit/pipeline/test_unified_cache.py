"""Tests for the unified cache integrations."""

import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.pipeline.cache import TTLMode, response_cache_fresh
from src.pipeline.cache_backend import PersistentCache
from src.pipeline.unified_cache import (
    Backend,
    CachePriority,
    CoalescingCacheWrapper,
    NAMESPACE_ROUTING,
    PRIORITY_RANK,
    UnifiedCache,
)


@pytest.mark.unit
class TestUnifiedCacheFACADE(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self._db = str(Path(self._tmp.name) / "cache.db")
        db = PersistentCache(db_path=self._db)
        self.cache = UnifiedCache(
            sqlite_backend=db,
            file_root=Path(self._tmp.name) / "blobs",
            strict_namespaces=False,
        )

    def tearDown(self) -> None:
        self.cache.close()

    def test_round_trip_sqlite_namespace(self) -> None:
        self.cache.set("probe:example.com:80", {"alive": True}, ttl=60)
        result = self.cache.get("probe:example.com:80")
        assert result == {"alive": True}

    def test_round_trip_file_namespace(self) -> None:
        payload = "x" * (32 * 1024)  # large enough to trigger file backend
        self.cache.set("screenshot:target:home", payload, ttl=60)
        result = self.cache.get("screenshot:target:home")
        assert result == payload

    def test_keys_with_prefix(self) -> None:
        self.cache.set("probe:a:1", {"v": 1})
        self.cache.set("probe:b:2", {"v": 2})
        self.cache.set("subdomain:x:y", {"v": 3})
        keys = self.cache.keys_with_prefix("probe:")
        assert sorted(keys) == ["probe:a:1", "probe:b:2"]

    def test_delete_removes_routing_and_data(self) -> None:
        self.cache.set("probe:del:1", {"v": 1})
        assert self.cache.delete("probe:del:1") is True
        assert self.cache.get("probe:del:1") is None

    def test_exists_reflects_liveness(self) -> None:
        self.cache.set("probe:live:1", {"v": 1}, ttl=60)
        assert self.cache.exists("probe:live:1") is True
        assert self.cache.exists("nonexistent") is False


@pytest.mark.unit
class TestUnifiedCachePRIORITY(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self._db = str(Path(self._tmp.name) / "cache.db")
        db = PersistentCache(db_path=self._db)
        self.cache = UnifiedCache(
            sqlite_backend=db,
            file_root=Path(self._tmp.name) / "blobs",
            strict_namespaces=False,
        )

    def tearDown(self) -> None:
        self.cache.close()

    def test_priority_queue_orders_critical_first(self) -> None:
        self.cache.set("resume:run:1", {"state": "saved"}, priority=CachePriority.CRITICAL)
        self.cache.set(
            "tool_output:cmd:1", {"stdout": "ok"}, priority=CachePriority.TRANSIENT
        )
        self.cache.set(
            "probe:target:1", {"v": 1}, priority=CachePriority.NORMAL
        )
        queue = self.cache.priority_queue()
        ranks = [PRIORITY_RANK[entry["priority"]] for entry in queue]
        assert ranks == sorted(ranks)

    def test_prune_oldest_protects_critical(self) -> None:
        for i in range(5):
            self.cache.set(
                f"resume:run:{i}", {"v": i}, priority=CachePriority.CRITICAL
            )
            self.cache.set(
                f"tool_output:cmd:{i}", {"v": i}, priority=CachePriority.TRANSIENT
            )
        removed = self.cache.prune_oldest(5, preserve_priority=CachePriority.CRITICAL)
        assert removed == 5
        for i in range(5):
            assert self.cache.get(f"resume:run:{i}") == {"v": i}

    def test_partition_by_stage_groups_namespaces(self) -> None:
        self.cache.set("probe:t:1", {"v": 1})
        self.cache.set("probe:t:2", {"v": 2})
        self.cache.set("subdomain:t:3", {"v": 3})
        partition = self.cache.partition_by_stage()
        assert len(partition["probe"]) == 2
        assert len(partition["subdomain"]) == 1


@pytest.mark.unit
class TestUnifiedCacheTTLMode(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self._db = str(Path(self._tmp.name) / "cache.db")
        db = PersistentCache(db_path=self._db)
        self.cache = UnifiedCache(
            sqlite_backend=db,
            file_root=Path(self._tmp.name) / "blobs",
            strict_namespaces=False,
        )

    def tearDown(self) -> None:
        self.cache.close()

    def test_stale_while_revalidate_invokes_callback(self) -> None:
        callback = MagicMock()
        self.cache.set(
            "http_response:target:url",
            {"cached_at_epoch": time.time() - 7200},
        )
        record = self.cache.routing_of("http_response:target:url")
        assert record is not None
        record["ttl_mode"] = TTLMode.STALE_WHILE_REVALIDATE.value
        self.cache._write_routing("http_response:target:url", record, ttl=1)
        cached = self.cache.get("http_response:target:url") or {}
        response_cache_fresh(
            cached,
            ttl_hours=1,
            ttl_mode=TTLMode.STALE_WHILE_REVALIDATE,
            background_callback=callback,
        )
        assert callback.called is True


@pytest.mark.unit
class TestCoalescingCacheWrapper(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self._db = str(Path(self._tmp.name) / "cache.db")
        db = PersistentCache(db_path=self._db)
        self.cache = UnifiedCache(
            sqlite_backend=db,
            file_root=Path(self._tmp.name) / "blobs",
            strict_namespaces=False,
        )

    def tearDown(self) -> None:
        self.cache.close()

    def test_coalescing_single_call(self) -> None:
        coalesce = self.cache.coalesce()
        call_log: list[str] = []

        def loader() -> str:
            call_log.append("called")
            return "loaded-value"

        coalesce.run_with_coalescing("probe:test:host", loader, ttl=60)
        assert call_log == ["called"]

        coalesce.run_with_coalescing("probe:test:host", loader, ttl=60)
        assert call_log == ["called"]

    def test_different_keys_independent(self) -> None:
        coalesce = self.cache.coalesce()

        def make_loader(value: str):
            def loader() -> str:
                return value

            return loader

        coalesce.run_with_coalescing("probe:a:1", make_loader("A"), ttl=60)
        coalesce.run_with_coalescing("probe:b:2", make_loader("B"), ttl=60)
        assert self.cache.get("probe:a:1") == "A"
        assert self.cache.get("probe:b:2") == "B"


@pytest.mark.unit
class TestNamespaceRouting(unittest.TestCase):
    def test_resume_namespaced_critical(self) -> None:
        routing = NAMESPACE_ROUTING["resume"]
        assert routing.default_priority == CachePriority.CRITICAL
        assert routing.default_backend == Backend.SQLITE

    def test_subdomain_namespaced_sqlite(self) -> None:
        routing = NAMESPACE_ROUTING["subdomain"]
        assert routing.default_backend == Backend.SQLITE
        assert routing.default_priority == CachePriority.NORMAL

    def test_tool_output_namespaced_file_transient(self) -> None:
        routing = NAMESPACE_ROUTING["tool_output"]
        assert routing.default_backend == Backend.FILE
        assert routing.default_priority == CachePriority.TRANSIENT


@pytest.mark.unit
class TestPriorityRankOrder(unittest.TestCase):
    def test_rank_order(self) -> None:
        assert PRIORITY_RANK[CachePriority.TRANSIENT.value] < PRIORITY_RANK[CachePriority.NORMAL.value]
        assert PRIORITY_RANK[CachePriority.NORMAL.value] < PRIORITY_RANK[CachePriority.CRITICAL.value]
