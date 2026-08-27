import unittest
from src.infrastructure.flow_control.bulkhead import (
    BulkheadPool,
    canonical_isolation_key,
)


class TestBulkheadEndpointIsolation(unittest.TestCase):
    def test_canonical_isolation_key_derivation(self) -> None:
        self.assertEqual(canonical_isolation_key("http://api.example.com/v1/scan"), "http://api.example.com:80")
        self.assertEqual(canonical_isolation_key("https://api.example.com:8443/test"), "https://api.example.com:8443")
        self.assertEqual(canonical_isolation_key("192.168.1.10:8080"), "https://192.168.1.10:8080")
        self.assertEqual(canonical_isolation_key("api.example.com"), "https://api.example.com:443")

    def test_unified_isolation_key_sharing_across_bulkhead_and_breaker(self) -> None:
        pool = BulkheadPool(default_max_concurrent=5)

        # Different paths under same endpoint share the exact same partition & circuit breaker
        part1 = pool.get_partition("https://api.example.com:443/users")
        part2 = pool.get_partition("https://api.example.com/orders")
        part3 = pool.get_partition("api.example.com")

        self.assertIs(part1, part2)
        self.assertIs(part2, part3)
        self.assertEqual(part1.endpoint_key, "https://api.example.com:443")
        self.assertEqual(part1.circuit_breaker.name, "https://api.example.com:443")

    def test_different_ports_or_schemes_isolated(self) -> None:
        pool = BulkheadPool(default_max_concurrent=5)

        part_http = pool.get_partition("http://api.example.com:80/status")
        part_https = pool.get_partition("https://api.example.com:443/status")
        part_custom = pool.get_partition("https://api.example.com:8443/status")

        self.assertIsNot(part_http, part_https)
        self.assertIsNot(part_https, part_custom)


if __name__ == "__main__":
    unittest.main()
