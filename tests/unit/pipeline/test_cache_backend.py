"""Unit tests for pipeline_platform.cache_backend module."""

import os
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.core.middleware.cache_bypass import CacheBypassMiddleware
from src.pipeline.cache import (
    load_cached_json,
    load_cached_set,
    response_cache_fresh,
    save_cached_json,
    save_cached_set,
)
from src.pipeline.cache_backend import PersistentCache


@pytest.mark.unit
class TestPersistentCacheGetSet(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        db_path = os.path.join(self._tmp.name, "test_cache.db")
        self.cache = PersistentCache(db_path=db_path)

    def tearDown(self) -> None:
        self.cache.close_all()
        import gc
        import time

        gc.collect()
        time.sleep(0.1)
        self._tmp.cleanup()

    def test_set_and_get_string_value(self) -> None:
        self.cache.set("key1", "hello")
        result = self.cache.get("key1")
        self.assertEqual(result, "hello")

    def test_set_and_get_integer(self) -> None:
        self.cache.set("key1", 42)
        result = self.cache.get("key1")
        self.assertEqual(result, 42)

    def test_set_and_get_dict(self) -> None:
        data = {"name": "test", "count": 5}
        self.cache.set("key1", data)
        result = self.cache.get("key1")
        self.assertEqual(result, data)

    def test_set_and_get_list(self) -> None:
        data = [1, 2, 3, "four"]
        self.cache.set("key1", data)
        result = self.cache.get("key1")
        self.assertEqual(result, data)

    def test_set_and_get_boolean(self) -> None:
        self.cache.set("key1", True)
        result = self.cache.get("key1")
        self.assertTrue(result)

    def test_set_and_get_none(self) -> None:
        self.cache.set("key1", None)
        result = self.cache.get("key1")
        self.assertIsNone(result)

    def test_get_missing_key_returns_none(self) -> None:
        result = self.cache.get("nonexistent")
        self.assertIsNone(result)

    def test_set_overwrites_existing_key(self) -> None:
        self.cache.set("key1", "old")
        self.cache.set("key1", "new")
        result = self.cache.get("key1")
        self.assertEqual(result, "new")

    def test_set_with_complex_nested_data(self) -> None:
        data = {
            "users": [{"id": 1, "name": "Alice"}, {"id": 2, "name": "Bob"}],
            "meta": {"total": 2, "page": 1},
        }
        self.cache.set("complex", data)
        result = self.cache.get("complex")
        self.assertEqual(result, data)


@pytest.mark.unit
class TestPersistentCacheTTL(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        db_path = os.path.join(self._tmp.name, "test_cache.db")
        self.cache = PersistentCache(db_path=db_path)

    def tearDown(self) -> None:
        self.cache.close_all()
        import gc
        import time

        gc.collect()
        time.sleep(0.1)
        self._tmp.cleanup()

    def test_get_before_ttl_expires(self) -> None:
        self.cache.set("key1", "value", ttl=60)
        result = self.cache.get("key1")
        self.assertEqual(result, "value")

    def test_get_after_ttl_expires(self) -> None:
        current_time = 1000.0
        with patch("time.time", side_effect=lambda: current_time):
            self.cache.set("key1", "value", ttl=1)
            current_time += 1.1
            result = self.cache.get("key1")
            self.assertIsNone(result)

    def test_set_without_ttl_persists_indefinitely(self) -> None:
        self.cache.set("key1", "value")
        result = self.cache.get("key1")
        self.assertEqual(result, "value")

    def test_expired_key_deleted_from_db(self) -> None:
        current_time = 1000.0
        with patch("time.time", side_effect=lambda: current_time):
            self.cache.set("key1", "value", ttl=1)
            current_time += 1.1
            self.cache.get("key1")
            self.assertEqual(self.cache.size(), 0)

    def test_update_ttl_on_overwrite(self) -> None:
        current_time = 1000.0
        with patch("time.time", side_effect=lambda: current_time):
            self.cache.set("key1", "value1", ttl=1)
            current_time += 0.5
            self.cache.set("key1", "value2", ttl=60)
            current_time += 0.6  # total 1.1 since first set, but key1 should be fresh
            result = self.cache.get("key1")
            self.assertEqual(result, "value2")


@pytest.mark.unit
class TestPersistentCacheDelete(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        db_path = os.path.join(self._tmp.name, "test_cache.db")
        self.cache = PersistentCache(db_path=db_path)

    def tearDown(self) -> None:
        self.cache.close_all()
        import gc
        import time

        gc.collect()
        time.sleep(0.1)
        self._tmp.cleanup()

    def test_delete_existing_key(self) -> None:
        self.cache.set("key1", "value")
        self.cache.delete("key1")
        result = self.cache.get("key1")
        self.assertIsNone(result)

    def test_delete_nonexistent_key_no_error(self) -> None:
        self.cache.delete("nonexistent")

    def test_delete_reduces_size(self) -> None:
        self.cache.set("key1", "value1")
        self.cache.set("key2", "value2")
        self.cache.delete("key1")
        self.assertEqual(self.cache.size(), 1)


@pytest.mark.unit
class TestPersistentCacheClear(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        db_path = os.path.join(self._tmp.name, "test_cache.db")
        self.cache = PersistentCache(db_path=db_path)

    def tearDown(self) -> None:
        self.cache.close_all()
        import gc
        import time

        gc.collect()
        time.sleep(0.1)
        self._tmp.cleanup()

    def test_clear_removes_all_entries(self) -> None:
        self.cache.set("key1", "value1")
        self.cache.set("key2", "value2")
        self.cache.set("key3", "value3")
        self.cache.clear()
        self.assertEqual(self.cache.size(), 0)

    def test_clear_empty_cache_no_error(self) -> None:
        self.cache.clear()
        self.assertEqual(self.cache.size(), 0)


@pytest.mark.unit
class TestPersistentCacheSize(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        db_path = os.path.join(self._tmp.name, "test_cache.db")
        self.cache = PersistentCache(db_path=db_path)

    def tearDown(self) -> None:
        self.cache.close_all()
        import gc
        import time

        gc.collect()
        time.sleep(0.1)
        self._tmp.cleanup()

    def test_size_empty_cache(self) -> None:
        self.assertEqual(self.cache.size(), 0)

    def test_size_after_adding_entries(self) -> None:
        self.cache.set("key1", "value1")
        self.cache.set("key2", "value2")
        self.assertEqual(self.cache.size(), 2)

    def test_size_after_overwrite(self) -> None:
        self.cache.set("key1", "value1")
        self.cache.set("key1", "value2")
        self.assertEqual(self.cache.size(), 1)


@pytest.mark.unit
class TestPersistentCacheCleanupExpired(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        db_path = os.path.join(self._tmp.name, "test_cache.db")
        self.cache = PersistentCache(db_path=db_path)

    def tearDown(self) -> None:
        self.cache.close_all()
        import gc
        import time

        gc.collect()
        time.sleep(0.1)
        self._tmp.cleanup()

    def test_cleanup_expired_entries(self) -> None:
        current_time = 1000.0
        with patch("time.time", side_effect=lambda: current_time):
            self.cache.set("key1", "value1", ttl=1)
            self.cache.set("key2", "value2", ttl=60)
            current_time += 1.1
            removed = self.cache.cleanup_expired()
            self.assertEqual(removed, 1)
            self.assertIsNone(self.cache.get("key1"))
            self.assertEqual(self.cache.get("key2"), "value2")

    def test_cleanup_no_expired(self) -> None:
        self.cache.set("key1", "value1", ttl=60)
        removed = self.cache.cleanup_expired()
        self.assertEqual(removed, 0)

    def test_cleanup_empty_cache(self) -> None:
        removed = self.cache.cleanup_expired()
        self.assertEqual(removed, 0)

    def test_cleanup_only_no_ttl_entries(self) -> None:
        self.cache.set("key1", "value1")
        removed = self.cache.cleanup_expired()
        self.assertEqual(removed, 0)
        self.assertEqual(self.cache.get("key1"), "value1")


@pytest.mark.unit
class TestPersistentCacheTelemetry(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        db_path = os.path.join(self._tmp.name, "test_cache.db")
        self.cache = PersistentCache(db_path=db_path)

    def tearDown(self) -> None:
        self.cache.close_all()
        import gc
        import time

        gc.collect()
        time.sleep(0.1)
        self._tmp.cleanup()

    def test_efficiency_snapshot_tracks_hit_miss_expiry_and_latency(self) -> None:
        current_time = 1000.0
        with patch("time.time", side_effect=lambda: current_time):
            self.cache.set("hit", "value", ttl=60)
            self.cache.set("expired", "stale", ttl=1)
            self.assertEqual(self.cache.get("hit"), "value")
            self.assertIsNone(self.cache.get("missing"))
            current_time += 2
            self.assertIsNone(self.cache.get("expired"))

        snapshot = self.cache.get_efficiency_snapshot()

        self.assertEqual(snapshot["backend_type"], "sqlite")
        self.assertEqual(snapshot["hits"], 1)
        self.assertEqual(snapshot["misses"], 2)
        self.assertEqual(snapshot["total_gets"], 3)
        self.assertAlmostEqual(snapshot["hit_ratio"], 1 / 3)
        self.assertEqual(snapshot["sets"], 2)
        self.assertEqual(snapshot["expirations"], 1)
        self.assertEqual(snapshot["backend_errors"], 0)
        self.assertGreaterEqual(snapshot["avg_get_latency_ms"], 0.0)

    def test_reset_metrics_clears_snapshot_counts(self) -> None:
        self.cache.set("key", "value")
        self.cache.get("key")
        self.cache.reset_metrics()

        snapshot = self.cache.get_efficiency_snapshot()

        self.assertEqual(snapshot["hits"], 0)
        self.assertEqual(snapshot["misses"], 0)
        self.assertEqual(snapshot["sets"], 0)


@pytest.mark.unit
class TestPersistentCacheThreadSafety(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        db_path = os.path.join(self._tmp.name, "test_cache.db")
        self.cache = PersistentCache(db_path=db_path)

    def tearDown(self) -> None:
        self.cache.close_all()
        import gc
        import time

        gc.collect()
        time.sleep(0.1)
        self._tmp.cleanup()

    def test_concurrent_set_get(self) -> None:
        errors: list[Exception] = []

        def writer(n: int) -> None:
            try:
                for i in range(20):
                    self.cache.set(f"key-{n}-{i}", f"value-{n}-{i}")
            except Exception as e:
                errors.append(e)

        def reader(n: int) -> None:
            try:
                for i in range(20):
                    self.cache.get(f"key-{n}-{i}")
            except Exception as e:
                errors.append(e)

        threads = []
        for n in range(3):
            threads.append(threading.Thread(target=writer, args=(n,)))
            threads.append(threading.Thread(target=reader, args=(n,)))

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(errors, [])


@pytest.mark.unit
class TestPersistentCacheValidateIntegrity(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        db_path = os.path.join(self._tmp.name, "test_cache.db")
        self.cache = PersistentCache(db_path=db_path)

    def tearDown(self) -> None:
        self.cache.close_all()
        import gc
        import time

        gc.collect()
        time.sleep(0.1)
        self._tmp.cleanup()

    def test_healthy_database(self) -> None:
        result = self.cache.validate_integrity()
        self.assertTrue(result["healthy"])
        self.assertEqual(result["issues"], [])

    def test_entry_count_reported(self) -> None:
        self.cache.set("key1", "value1")
        self.cache.set("key2", "value2")
        result = self.cache.validate_integrity()
        self.assertEqual(result["entry_count"], 2)

    def test_db_size_reported(self) -> None:
        result = self.cache.validate_integrity()
        self.assertGreater(result["db_size_bytes"], 0)

    def test_nonexistent_database(self) -> None:
        db_path = os.path.join(self._tmp.name, "nonexistent", "cache.db")
        cache = PersistentCache(db_path=db_path)
        result = cache.validate_integrity()
        self.assertTrue(result["healthy"])
        self.assertEqual(result["issues"], [])

    def test_large_database_warning(self) -> None:
        with patch.object(Path, "stat") as mock_stat:
            mock_stat.return_value = MagicMock(st_size=200 * 1024 * 1024)
            result = self.cache.validate_integrity()
            self.assertTrue(result["healthy"])
            self.assertTrue(any("large" in issue.lower() for issue in result["issues"]))


@pytest.mark.unit
class TestPersistentCacheRecoverFromCorruption(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        db_path = os.path.join(self._tmp.name, "test_cache.db")
        self.cache = PersistentCache(db_path=db_path)

    def tearDown(self) -> None:
        self.cache.close_all()
        import gc
        import time

        gc.collect()
        time.sleep(0.1)
        self._tmp.cleanup()

    def test_healthy_database_returns_true(self) -> None:
        result = self.cache.recover_from_corruption()
        self.assertTrue(result)

    def test_nonexistent_database_recreates(self) -> None:
        cache = PersistentCache(db_path=os.path.join(self._tmp.name, "new", "cache.db"))
        result = cache.recover_from_corruption()
        self.assertTrue(result)

    def test_corrupted_database_recreates(self) -> None:
        db_path = os.path.join(self._tmp.name, "test_cache.db")
        self.cache._close_conn()
        with open(db_path, "wb") as f:
            f.write(b"not a valid sqlite database")
        result = self.cache.recover_from_corruption()
        self.assertTrue(result)
        self.cache.set("key1", "value1")
        self.assertEqual(self.cache.get("key1"), "value1")


@pytest.mark.unit
class TestPersistentCacheGetDiskUsage(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        db_path = os.path.join(self._tmp.name, "test_cache.db")
        self.cache = PersistentCache(db_path=db_path)

    def tearDown(self) -> None:
        self.cache.close_all()
        import gc
        import time

        gc.collect()
        time.sleep(0.1)
        self._tmp.cleanup()

    def test_returns_usage_info(self) -> None:
        self.cache.set("key1", "value1")
        usage = self.cache.get_disk_usage()
        self.assertIn("db_path", usage)
        self.assertIn("db_size_bytes", usage)
        self.assertIn("entry_count", usage)
        self.assertEqual(usage["entry_count"], 1)
        self.assertGreater(usage["db_size_bytes"], 0)

    def test_nonexistent_db_path(self) -> None:
        cache = PersistentCache(db_path=os.path.join(self._tmp.name, "nonexistent", "cache.db"))
        usage = cache.get_disk_usage()
        self.assertGreater(usage["db_size_bytes"], 0)
        self.assertEqual(usage["entry_count"], 0)


@pytest.mark.unit
class TestPersistentCacheEdgeCases(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        db_path = os.path.join(self._tmp.name, "test_cache.db")
        self.cache = PersistentCache(db_path=db_path)

    def tearDown(self) -> None:
        self.cache.close_all()
        import gc
        import time

        gc.collect()
        time.sleep(0.1)
        self._tmp.cleanup()

    def test_set_empty_string(self) -> None:
        self.cache.set("key1", "")
        self.assertEqual(self.cache.get("key1"), "")

    def test_set_empty_dict(self) -> None:
        self.cache.set("key1", {})
        self.assertEqual(self.cache.get("key1"), {})

    def test_set_empty_list(self) -> None:
        self.cache.set("key1", [])
        self.assertEqual(self.cache.get("key1"), [])

    def test_set_zero(self) -> None:
        self.cache.set("key1", 0)
        self.assertEqual(self.cache.get("key1"), 0)

    def test_set_false(self) -> None:
        self.cache.set("key1", False)
        self.assertEqual(self.cache.get("key1"), False)

    def test_set_float_value(self) -> None:
        self.cache.set("key1", 3.14159)
        self.assertEqual(self.cache.get("key1"), 3.14159)

    def test_ttl_zero_expires_immediately(self) -> None:
        self.cache.set("key1", "value", ttl=0)
        result = self.cache.get("key1")
        self.assertIsNone(result)

    def test_negative_ttl_expires_immediately(self) -> None:
        self.cache.set("key1", "value", ttl=-10)
        result = self.cache.get("key1")
        self.assertIsNone(result)

    def test_corrupt_json_entry_is_deleted_on_read(self) -> None:
        conn = sqlite3.connect(self.cache._db_path)
        conn.execute(
            "INSERT OR REPLACE INTO cache_entries (key, value, created_at, expires_at) VALUES (?, ?, ?, ?)",
            ("bad-json", "{not-json", 1000.0, None),
        )
        conn.commit()
        conn.close()

        self.assertIsNone(self.cache.get("bad-json"))
        self.assertEqual(self.cache.size(), 0)


@pytest.mark.unit
class TestPipelineCacheUtilities(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.cache_dir = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_compressed_set_replaces_stale_uncompressed_file(self) -> None:
        path = self.cache_dir / "items.json"
        save_cached_set(path, {"old"}, compress=False)
        save_cached_set(path, {"new"}, compress=True)

        self.assertFalse(path.exists())
        self.assertEqual(load_cached_set(path), {"new"})

    def test_compressed_json_replaces_stale_uncompressed_file(self) -> None:
        path = self.cache_dir / "payload.json"
        save_cached_json(path, {"value": "old"}, compress=False)
        save_cached_json(path, {"value": "new"}, compress=True)

        self.assertFalse(path.exists())
        self.assertEqual(load_cached_json(path), {"value": "new"})

    def test_response_cache_fresh_rejects_invalid_timestamp(self) -> None:
        self.assertFalse(response_cache_fresh({"cached_at_epoch": "not-a-float"}, 24))


@pytest.mark.unit
class TestCacheBypassMiddleware(unittest.TestCase):
    def test_add_cache_busting_does_not_mutate_input(self) -> None:
        middleware = CacheBypassMiddleware()
        original = {"Authorization": "Bearer token"}

        updated = middleware.add_cache_busting(original)

        self.assertEqual(original, {"Authorization": "Bearer token"})
        self.assertEqual(updated["Cache-Control"], "no-cache, no-store, must-revalidate")

    def test_process_request_accepts_none(self) -> None:
        middleware = CacheBypassMiddleware()

        self.assertEqual(
            middleware.process_request_with_cache_bypass(None),
            {
                "Cache-Control": "no-cache, no-store, must-revalidate",
                "Pragma": "no-cache",
                "Expires": "0",
            },
        )


if __name__ == "__main__":
    unittest.main()
