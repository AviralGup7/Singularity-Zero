import unittest

from src.infrastructure.queue.redis_client import RedisClient


class TestRedisQueueCircuitBreaker(unittest.TestCase):
    def test_redis_client_fallback_and_health_status(self) -> None:
        # Client initialized without URL defaults safely to local disk / SQLite fallback
        client = RedisClient(url=None)
        self.assertTrue(client._use_fallback)
        self.assertFalse(client._healthy)

        health = client.get_health_status()
        self.assertFalse(health["healthy"])
        self.assertTrue(health["use_fallback"])
        self.assertIn("circuit_breaker_state", health)
        self.assertIn("local_queue.db", health["fallback_db_path"])

        # Commands succeed via fallback emulator
        res = client.execute_command("PING")
        self.assertEqual(res, "PONG")


if __name__ == "__main__":
    unittest.main()
