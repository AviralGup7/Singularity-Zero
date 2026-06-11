import ipaddress
import socket
import sys
import types

_original_getaddrinfo = socket.getaddrinfo


def _mock_getaddrinfo(host, port, *args, **kwargs):
    """Offline DNS resolver: routes external hostnames to 8.8.8.8.
    Localhost / literal IPs are preserved.  Cloud metadata and
    link-local addresses are blocked to surface SSRF bugs."""
    family = kwargs.get("family") or (args[0] if args else 0)
    if not host:
        return _original_getaddrinfo(host, port, *args, **kwargs)
    if host in ("localhost", "127.0.0.1", "0.0.0.0", "::1"):  # noqa: S104
        if family == socket.AF_INET6:
            return [
                (socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("::1", port or 80))
            ]
        return [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("127.0.0.1", port or 80))
        ]
    try:
        ip = ipaddress.ip_address(host)
        if isinstance(ip, ipaddress.IPv4Address) and ip.is_link_local:
            raise OSError(f"DNS resolution blocked for link-local address: {host}")
        if host == "169.254.169.254":
            raise OSError(f"DNS resolution blocked for cloud metadata endpoint: {host}")
        if family == socket.AF_INET6 and isinstance(ip, ipaddress.IPv4Address):
            mapped = f"::ffff:{ip}"
            return [
                (socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (mapped, port or 80))
            ]
        if family == socket.AF_INET and isinstance(ip, ipaddress.IPv6Address):
            return [
                (
                    socket.AF_INET,
                    socket.SOCK_STREAM,
                    socket.IPPROTO_TCP,
                    "",
                    ("127.0.0.1", port or 80),
                )
            ]
        sock_family = socket.AF_INET6 if isinstance(ip, ipaddress.IPv6Address) else socket.AF_INET
        return [(sock_family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (str(ip), port or 80))]
    except ValueError:
        pass
    if family == socket.AF_INET6:
        return [
            (
                socket.AF_INET6,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                ("::ffff:8.8.8.8", port or 80),
            )
        ]
    return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("8.8.8.8", port or 80))]


def _setup_pykka_compat():
    """Set up a minimal pykka compatibility shim if pykka is not installed."""
    try:
        import pykka  # noqa: F401
    except (ImportError, AttributeError):

        class ActorDeadError(Exception):
            pass

        class ActorTimeout(Exception):
            pass

        class PykkaCompatibility(types.ModuleType):
            ActorDeadError = ActorDeadError
            Timeout = ActorTimeout
            ActorDeadError.__module__ = "pykka"
            ActorTimeout.__module__ = "pykka"

        sys.modules["pykka"] = PykkaCompatibility("pykka")


_setup_pykka_compat()

import tempfile  # noqa: E402
from collections.abc import Generator  # noqa: E402
from pathlib import Path  # noqa: E402
from typing import Any  # noqa: E402

import pytest  # noqa: E402
from tests.factories import (  # noqa: E402
    ConfigBuilder,
    FindingBuilder,
    RequestBuilder,
    ResponseBuilder,
)


@pytest.fixture
def test_db(tmp_path: Path) -> Generator[Path]:
    """Provide a temporary SQLite database for integration tests.

    Creates a fresh database file in a temporary directory and yields
    the path. The database is automatically cleaned up after the test.
    """
    db_path = tmp_path / "test.db"
    yield db_path
    # Cleanup is handled by tmp_path automatically


@pytest.fixture
def test_db_url(test_db: Path) -> str:
    """Provide a SQLite database URL for SQLAlchemy."""
    return f"sqlite:///{test_db}"


@pytest.fixture
def offline_dns(monkeypatch: pytest.MonkeyPatch) -> Generator[None]:
    """Opt-in fixture: route external DNS lookups to 8.8.8.8 so tests
    run in offline sandboxes. Localhost / literal IPs are preserved.
    Use this in tests that make real network calls."""
    monkeypatch.setattr(socket, "getaddrinfo", _mock_getaddrinfo)
    yield


@pytest.fixture
def mock_resource_guard(monkeypatch: pytest.MonkeyPatch) -> Generator[None]:
    """Opt-in fixture: disable ResourceGuard checks during tests to
    prevent host-RAM dependency. Use only when ResourceGuard would
    interfere with the code under test."""
    try:
        from src.infrastructure.resource_guard import ResourceGuard

        monkeypatch.setattr(
            ResourceGuard,
            "should_skip_stage",
            lambda *args, **kwargs: (False, None),
        )
        monkeypatch.setattr(
            ResourceGuard,
            "check_critical_oom",
            lambda *args, **kwargs: None,
        )
        monkeypatch.setattr(
            ResourceGuard,
            "check_and_halt_on_oom",
            lambda *args, **kwargs: None,
        )
        monkeypatch.setattr(
            ResourceGuard,
            "get_concurrency_cap",
            lambda self, stage_name, default: default,
        )
    except ImportError:
        pass
    yield


@pytest.fixture(autouse=True)
def _mock_run_lock_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Generator[None]:
    """Mock the RunLock cache directory to use a temporary path per test to avoid pollution."""
    try:
        import src.infrastructure.task_pool

        monkeypatch.setattr(src.infrastructure.task_pool, "_CACHE_DIR", tmp_path / "run_lock")
    except ImportError:
        pass
    yield


@pytest.fixture
def temp_workspace() -> Generator[Path]:
    """Provide a temporary workspace directory for tests."""
    with tempfile.TemporaryDirectory() as tmp:
        yield Path(tmp)


@pytest.fixture
def sample_config_json() -> str:
    """Return a minimal valid configuration JSON string."""
    return (
        '{"target_name":"example.com","output_dir":"output",'
        '"concurrency":{"nuclei_workers":2},'
        '"output":{"dedupe_aliases":true}}'
    )


@pytest.fixture
def sample_scope() -> str:
    """Return a sample scope definition."""
    return "example.com\napi.example.com"


@pytest.fixture
def sample_config() -> dict[str, Any]:
    """Return a sample Config dict built with ConfigBuilder."""
    return ConfigBuilder().build()


@pytest.fixture
def sample_finding() -> dict[str, Any]:
    """Return a sample security finding dict built with FindingBuilder."""
    return FindingBuilder().build()


@pytest.fixture
def sample_request() -> dict[str, Any]:
    """Return a sample HTTP request dict built with RequestBuilder."""
    return RequestBuilder().build()


def make_response(
    url: str, status_code: int = 200, body: str = "", headers: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Create a mock response dict for testing."""
    return {
        "url": url,
        "status_code": status_code,
        "body": body,
        "headers": headers or {},
        "response_time": 0.1,
        "redirect_chain": [],
    }


@pytest.fixture
def sample_response() -> dict[str, Any]:
    """Return a sample HTTP response dict built with ResponseBuilder."""
    return ResponseBuilder().build()


@pytest.fixture
def sample_url() -> str:
    """Return a sample URL string for testing."""
    return "https://example.com/api/v1/test"


@pytest.fixture
def response_factory() -> Any:
    """Factory fixture for creating mock response dicts."""
    return make_response
