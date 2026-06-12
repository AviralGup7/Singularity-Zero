import ipaddress
import socket
import sys
import types

import pytest

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
    except ImportError:
        import threading
        import time as _time

        class ActorDeadError(Exception):
            pass

        class ActorTimeout(Exception):
            pass

        class _Future:
            def __init__(self, value=None, error=None):
                self._value = value
                self._error = error
                self._event = threading.Event()

            def set(self, value=None, error=None):
                self._value = value
                self._error = error
                self._event.set()

            def get(self, timeout=None):
                self._event.wait(timeout=timeout)
                if self._error is not None:
                    raise self._error
                return self._value

        class ActorRef:
            def __init__(self, actor_instance):
                self._actor = actor_instance
                self._alive = True

            def ask(self, message, block=False, timeout=None):
                try:
                    result = self._actor.on_receive(message)
                    if block:
                        return result
                    return result
                except Exception as exc:
                    if isinstance(exc, (ActorDeadError, ActorTimeout)):
                        raise
                    raise

            def stop(self, block=True):
                self._alive = False
                if hasattr(self._actor, "_thread") and self._actor._thread.is_alive():
                    self._actor._stop_event.set()
                    if block:
                        self._actor._thread.join(timeout=5)

            def is_alive(self):
                return (
                    self._alive
                    and self._actor._stop_event is not None
                    and not self._actor._stop_event.is_set()
                )

            def proxy(self):
                return _ActorProxy(self)

        class _ActorProxy:
            def __init__(self, ref):
                self._ref = ref

            def __getattr__(self, name):
                if name.startswith("_"):
                    raise AttributeError(name)
                return _ProxyAttr(self._ref, name)

        class _ProxyAttr:
            def __init__(self, ref, name):
                self._ref = ref
                self._name = name

            def get(self, timeout=None):
                return self._ref.ask(
                    {"command": "__getattribute__", "name": self._name}, block=True, timeout=timeout
                )

            def __call__(self, *args, **kwargs):
                return self._ref.ask(
                    {"command": "__call__", "name": self._name, "args": args, "kwargs": kwargs},
                    block=True,
                )

            def __setattr__(self, name, value):
                if name.startswith("_"):
                    object.__setattr__(self, name, value)
                else:
                    self._ref.ask(
                        {"command": "__setattr__", "name": name, "value": value}, block=True
                    )

        class Actor:
            def __init__(self):
                self._stop_event = threading.Event()
                self._thread = None

            @classmethod
            def start(cls, *args, **kwargs):
                actor_instance = cls(*args, **kwargs)
                ref = ActorRef(actor_instance)
                t = threading.Thread(target=actor_instance._run, daemon=True)
                actor_instance._thread = t
                actor_instance._ref = ref
                t.start()
                return ref

            def _run(self):
                while not self._stop_event.is_set():
                    _time.sleep(0.01)

            def stop(self):
                self._stop_event.set()

            def on_receive(self, message):
                raise NotImplementedError("Subclasses must implement on_receive")

        pykka_mod = types.ModuleType("pykka")
        pykka_mod.Actor = Actor
        pykka_mod.ThreadingActor = Actor
        pykka_mod.ActorRef = ActorRef
        pykka_mod.ActorDeadError = ActorDeadError
        pykka_mod.Timeout = ActorTimeout
        ActorDeadError.__module__ = "pykka"
        ActorTimeout.__module__ = "pykka"
        sys.modules["pykka"] = pykka_mod


_setup_pykka_compat()

import tempfile  # noqa: E402
from collections.abc import Generator  # noqa: E402
from pathlib import Path  # noqa: E402
from typing import Any  # noqa: E402

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
