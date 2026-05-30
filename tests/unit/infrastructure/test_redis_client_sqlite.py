"""Unit tests for the persistent SQLite fallback backend of RedisClient."""

import os
import unittest
from pathlib import Path

import pytest

from src.infrastructure.queue.redis_client import RedisClient


@pytest.mark.unit
class TestRedisClientSqlite(unittest.TestCase):
    def setUp(self) -> None:
        """Create a clean sandbox directory and initialize client with fallback."""
        self.output_dir = Path("output")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.output_dir / "local_queue.db"

        # Clean existing test DB if present
        if self.db_path.exists():
            try:
                os.remove(self.db_path)
            except OSError:
                pass

        # URL=None triggers fallback mode
        self.client = RedisClient(url=None)

    def tearDown(self) -> None:
        """Close client and clean up database files."""
        self.client.close()
        if self.db_path.exists():
            try:
                os.remove(self.db_path)
            except OSError:
                pass

    def test_fallback_activation(self) -> None:
        """Verify that fallback mode activates correctly when URL is None."""
        self.assertTrue(self.client._use_fallback)
        self.assertTrue(self.client.is_healthy)
        self.assertIsNone(self.client.client)

    def test_basic_get_set_del(self) -> None:
        """Verify standard GET, SET, and DEL operations on the persistent fallback."""
        # Check non-existent
        val = self.client.execute_command("GET", "test_key")
        self.assertIsNone(val)

        # Set value
        res = self.client.execute_command("SET", "test_key", "hello_world")
        self.assertTrue(res)

        # Get value
        val = self.client.execute_command("GET", "test_key")
        self.assertEqual(val, "hello_world")

        # Delete value
        deleted = self.client.execute_command("DEL", "test_key")
        self.assertEqual(deleted, 1)

        # Get again
        val = self.client.execute_command("GET", "test_key")
        self.assertIsNone(val)

    def test_hash_operations(self) -> None:
        """Verify hash operations (HSET, HGET, HGETALL, HDEL, HINCRBY)."""
        # HSET mapping
        self.client.execute_command("HSET", "myhash", mapping={"field1": "val1", "field2": "val2"})

        # HGET
        f1 = self.client.execute_command("HGET", "myhash", "field1")
        self.assertEqual(f1, b"val1")  # Decodes to bytes just like standard redis client wrapper

        # HGETALL
        all_data = self.client.execute_command("HGETALL", "myhash")
        self.assertEqual(all_data, {b"field1": b"val1", b"field2": b"val2"})

        # HINCRBY
        self.client.execute_command("HSET", "myhash", "counter", "10")
        new_val = self.client.execute_command("HINCRBY", "myhash", "counter", 5)
        self.assertEqual(new_val, 15)
        val = self.client.execute_command("HGET", "myhash", "counter")
        self.assertEqual(val, b"15")

        # HDEL
        self.client.execute_command("HDEL", "myhash", "field1")
        all_data_after = self.client.execute_command("HGETALL", "myhash")
        self.assertNotIn(b"field1", all_data_after)
        self.assertIn(b"field2", all_data_after)

    def test_set_operations(self) -> None:
        """Verify set operations (SADD, SREM, SMEMBERS)."""
        # SADD
        added = self.client.execute_command("SADD", "myset", "member1", "member2")
        self.assertEqual(added, 2)

        # SMEMBERS
        members = self.client.execute_command("SMEMBERS", "myset")
        self.assertEqual(len(members), 2)
        self.assertIn(b"member1", members)
        self.assertIn(b"member2", members)

        # SREM
        removed = self.client.execute_command("SREM", "myset", "member1")
        self.assertEqual(removed, 1)

        members_after = self.client.execute_command("SMEMBERS", "myset")
        self.assertEqual(members_after, [b"member2"])

    def test_sorted_set_operations(self) -> None:
        """Verify sorted set operations (ZADD, ZREM, ZCARD, ZSCORE, ZRANGEBYSCORE)."""
        # ZADD
        self.client.execute_command("ZADD", "myzset", 1.5, "member1")
        self.client.execute_command("ZADD", "myzset", 2.5, "member2")
        self.client.execute_command("ZADD", "myzset", 0.5, "member3")

        # ZCARD
        self.assertEqual(self.client.execute_command("ZCARD", "myzset"), 3)

        # ZSCORE
        self.assertEqual(self.client.execute_command("ZSCORE", "myzset", "member1"), b"1.5")

        # ZRANGEBYSCORE (ordered ascending)
        items = self.client.execute_command("ZRANGEBYSCORE", "myzset", "-inf", "+inf")
        self.assertEqual(items, [b"member3", b"member1", b"member2"])

        # ZREM
        self.client.execute_command("ZREM", "myzset", "member1")
        self.assertEqual(self.client.execute_command("ZCARD", "myzset"), 2)

    def test_list_operations(self) -> None:
        """Verify list operations (LPUSH, RPOP, LLEN)."""
        # LPUSH
        self.client.execute_command("LPUSH", "mylist", "val1", "val2")
        self.assertEqual(self.client.execute_command("LLEN", "mylist"), 2)

        # RPOP (val1 pushed first, so popped first from right)
        popped = self.client.execute_command("RPOP", "mylist")
        self.assertEqual(popped, b"val1")
        self.assertEqual(self.client.execute_command("LLEN", "mylist"), 1)

    def test_database_persistence(self) -> None:
        """CRITICAL TEST: Verify that data persists across separate client instances (distinct processes)."""
        # Set value in first client
        self.client.execute_command("SET", "persist_key", "persisted_value")
        self.client.execute_command("HSET", "persist_hash", "field", "hash_value")
        self.client.close()

        # Instantiate a completely fresh client loading the same SQLite file
        new_client = RedisClient(url=None)

        # Verify strings are loaded correctly
        val = new_client.execute_command("GET", "persist_key")
        self.assertEqual(val, "persisted_value")

        # Verify complex data structures are loaded correctly
        hash_val = new_client.execute_command("HGET", "persist_hash", "field")
        self.assertEqual(hash_val, b"hash_value")

        new_client.close()
