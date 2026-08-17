"""Behavioral coverage for the previously untested exception hierarchy."""

from __future__ import annotations

import pytest

from src.core.exceptions import (
    AuthError,
    CacheError,
    CircuitBreakerOpenError,
    ConfigError,
    DatabaseUnavailableError,
    ExternalToolError,
    FindingError,
    PipelineError,
    RedisDegradedError,
    ReplayError,
    ScopeViolationError,
    StageError,
    ToolNotInstalledError,
)

ALL_ERRORS = [
    PipelineError,
    ConfigError,
    StageError,
    FindingError,
    ReplayError,
    AuthError,
    CacheError,
    ExternalToolError,
    ScopeViolationError,
    ToolNotInstalledError,
    CircuitBreakerOpenError,
    DatabaseUnavailableError,
    RedisDegradedError,
]


@pytest.mark.unit
@pytest.mark.parametrize("exc_cls", ALL_ERRORS)
def test_each_exception_is_pipeline_error(exc_cls: type[PipelineError]) -> None:
    err = exc_cls("boom")
    assert isinstance(err, PipelineError)
    assert isinstance(err, Exception)
    assert "boom" in str(err)
    assert err.message
    assert isinstance(err.details, dict)


@pytest.mark.unit
@pytest.mark.parametrize("exc_cls", ALL_ERRORS)
def test_details_default_to_empty_dict(exc_cls: type[PipelineError]) -> None:
    err = exc_cls("x")
    assert err.details == {}
    err.details["k"] = "v"
    assert err.details["k"] == "v"


@pytest.mark.unit
def test_stage_error_records_stage_name() -> None:
    err = StageError("failed", stage="recon", details={"code": 7})
    assert err.stage == "recon"
    assert err.details["code"] == 7


@pytest.mark.unit
def test_external_tool_error_records_tool_and_exit() -> None:
    err = ExternalToolError("nuclei crashed", tool="nuclei", exit_code=2)
    assert err.tool == "nuclei"
    assert err.exit_code == 2


@pytest.mark.unit
def test_scope_violation_carries_target_and_hosts() -> None:
    err = ScopeViolationError(
        "out of scope",
        target_url="https://evil.example",
        reason="host",
        scope_hosts=["good.example"],
    )
    assert err.target_url == "https://evil.example"
    assert err.reason == "host"
    assert err.scope_hosts == ["good.example"]


@pytest.mark.unit
def test_tool_not_installed_has_stable_error_code() -> None:
    err = ToolNotInstalledError("missing", tool="httpx")
    assert err.tool == "httpx"
    assert err.error_code == "tool_not_installed"


@pytest.mark.unit
def test_circuit_breaker_open_has_stable_error_code() -> None:
    err = CircuitBreakerOpenError("open", tool="katana", breaker_state="open")
    assert err.tool == "katana"
    assert err.breaker_state == "open"
    assert err.error_code == "circuit_breaker_open"


@pytest.mark.unit
def test_database_unavailable_default_message() -> None:
    err = DatabaseUnavailableError()
    assert "unavailable" in err.message.lower()
    assert err.error_code == "database_unavailable"


@pytest.mark.unit
def test_redis_degraded_default_message() -> None:
    err = RedisDegradedError()
    assert "redis" in err.message.lower()
    assert err.error_code == "redis_degraded"


@pytest.mark.unit
@pytest.mark.parametrize(
    "exc_cls",
    [ConfigError, FindingError, ReplayError, AuthError, CacheError],
)
def test_simple_subclasses_preserve_custom_details(exc_cls: type[PipelineError]) -> None:
    err = exc_cls("bad", details={"field": "timeout"})
    assert err.details["field"] == "timeout"
