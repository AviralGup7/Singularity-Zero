import unittest

from src.infrastructure.observability.config import MetricsConfig, ObservabilityConfig


class TestPrometheusSecurityConfig(unittest.TestCase):
    def test_default_prometheus_binding_is_localhost(self) -> None:
        cfg = MetricsConfig()
        # Default must be localhost (127.0.0.1) rather than 0.0.0.0 to prevent network reconnaissance leaks
        self.assertEqual(cfg.prometheus_host, "127.0.0.1")
        self.assertEqual(cfg.prometheus_port, 9090)
        self.assertFalse(cfg.prometheus_require_mtls)
        self.assertIsNone(cfg.prometheus_bearer_token)

    def test_observability_from_env_defaults(self) -> None:
        obs_cfg = ObservabilityConfig.from_env()
        self.assertEqual(obs_cfg.metrics.prometheus_host, "127.0.0.1")


if __name__ == "__main__":
    unittest.main()
