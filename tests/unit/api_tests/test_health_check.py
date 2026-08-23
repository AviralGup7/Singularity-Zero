"""api_tests.health_check must not depend on a missing APITestClient class."""

from src.api_tests import health_check


def test_health_check_returns_ok_without_api_test_client() -> None:
    result = health_check()
    assert result["status"] == "ok"
    assert result["module"] == "api_tests"
    assert "APITestClient" not in repr(result)
    assert "errors" not in result
