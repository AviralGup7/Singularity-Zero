import asyncio
import unittest

from src.infrastructure.observability.health_checks import (
    ComponentHealth,
    ComponentStatus,
    HealthChecker,
    HealthCheckResult,
    HealthStatus,
)


class TestHealthChecker(unittest.TestCase):
    def test_register_and_get_component(self) -> None:
        checker = HealthChecker()

        async def healthy_check() -> ComponentHealth:
            return ComponentHealth(name="test", status=ComponentStatus.UP)

        checker.register("test", healthy_check)
        component = checker.get_component("test")
        assert component is not None
        assert component.name == "test"

    def test_unregister(self) -> None:
        checker = HealthChecker()

        async def dummy_check() -> ComponentHealth:
            return ComponentHealth(name="test")

        checker.register("test", dummy_check)
        checker.unregister("test")
        assert checker.get_component("test") is None

    def test_check_component_no_handler(self) -> None:
        checker = HealthChecker()
        result = asyncio.run(checker.check_component("missing"))
        assert result.status == ComponentStatus.UNKNOWN

    def test_check_all_empty(self) -> None:
        checker = HealthChecker()
        result = asyncio.run(checker.check_all())
        assert result.overall_status == HealthStatus.HEALTHY

    def test_get_history_empty(self) -> None:
        checker = HealthChecker()
        assert checker.get_history() == []

    def test_get_trend_empty(self) -> None:
        checker = HealthChecker()
        trend = checker.get_trend()
        assert trend["trend"] == "unknown"

    def test_get_last_result_none(self) -> None:
        checker = HealthChecker()
        assert checker.get_last_result() is None

    def test_get_summary(self) -> None:
        checker = HealthChecker()
        summary = checker.get_summary()
        assert "overall_status" in summary
        assert "component_count" in summary

    def test_health_check_result_to_dict(self) -> None:
        result = HealthCheckResult(
            overall_status=HealthStatus.HEALTHY,
            version="1.0.0",
            duration_ms=10.5,
        )
        d = result.to_dict()
        assert d["overall_status"] == "healthy"
        assert d["version"] == "1.0.0"

    def test_health_check_result_to_json(self) -> None:
        result = HealthCheckResult(overall_status=HealthStatus.HEALTHY)
        json_str = result.to_json()
        assert "healthy" in json_str

    def test_component_health_to_dict(self) -> None:
        health = ComponentHealth(name="redis", status=ComponentStatus.UP, message="ok")
        d = health.to_dict()
        assert d["name"] == "redis"
        assert d["status"] == "up"
        assert d["message"] == "ok"
