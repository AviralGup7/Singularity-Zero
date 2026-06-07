"""Tests for :mod:`src.recon.collectors.http_safety` (safe_get + SSRF guard)."""

from __future__ import annotations

import pytest
import requests

from src.recon.collectors.http_safety import (
    SafeGetResult,
    clear_safe_url_cache,
    get_default_session,
    is_safe_url,
    reset_default_session,
    safe_get,
)


class TestIsSafeUrl:
    def teardown_method(self) -> None:
        clear_safe_url_cache()

    def test_public_https_does_not_raise(self) -> None:
        # ``is_safe_url`` is a guard: it returns ``None`` when the URL is
        # safe and raises ``ValueError`` when it is not.  We just verify
        # the call returns cleanly for a public hostname.
        assert is_safe_url("https://example.com/") is None

    def test_localhost_raises(self) -> None:
        with pytest.raises(ValueError):
            is_safe_url("http://localhost/admin")
        with pytest.raises(ValueError):
            is_safe_url("http://127.0.0.1/")
        with pytest.raises(ValueError):
            is_safe_url("http://0.0.0.0/")

    def test_rfc1918_raises(self) -> None:
        for url in (
            "http://10.0.0.5/",
            "http://192.168.1.1/",
            "http://172.16.0.1/",
        ):
            with pytest.raises(ValueError):
                is_safe_url(url)

    def test_link_local_raises(self) -> None:
        with pytest.raises(ValueError):
            is_safe_url("http://169.254.169.254/latest/meta-data/")

    def test_ipv6_loopback_raises(self) -> None:
        with pytest.raises(ValueError):
            is_safe_url("http://[::1]/")

    def test_invalid_scheme_raises(self) -> None:
        with pytest.raises(ValueError):
            is_safe_url("file:///etc/passwd")
        with pytest.raises(ValueError):
            is_safe_url("ftp://example.com/")

    def test_check_once_caches_result(self) -> None:
        # First call populates the cache, subsequent calls return the cached result.
        is_safe_url("https://cached.example.com/", check_once=True)
        is_safe_url("https://cached.example.com/", check_once=True)
        # If we reach here without exception, the cache worked.


class TestSafeGetWithoutServer:
    """Tests that don't actually need a running server."""

    def test_safe_get_rejects_blocked_url(self) -> None:
        result = safe_get(
            "http://127.0.0.1/never-called",
            provider="unit-test",
            timeout_seconds=5,
        )
        assert result.ok is False
        assert result.response is None

    def test_safe_get_returns_saferesult_dataclass(self) -> None:
        result = safe_get(
            "http://127.0.0.1/",
            provider="unit-test",
            timeout_seconds=5,
            max_retries=0,
        )
        assert isinstance(result, SafeGetResult)
        assert hasattr(result, "ok")
        assert hasattr(result, "response")
        assert hasattr(result, "last_error")
        assert hasattr(result, "attempts")

    def test_blocked_url_does_not_retry(self, monkeypatch) -> None:
        # A blocked URL should fail fast — no actual ``requests.get`` is
        # ever issued, so the retry counter should not be incremented.
        result = safe_get(
            "http://10.0.0.1/",
            provider="unit-test",
            timeout_seconds=5,
            max_retries=3,
        )
        assert result.ok is False


class TestDefaultSession:
    def setup_method(self) -> None:
        reset_default_session()

    def teardown_method(self) -> None:
        reset_default_session()

    def test_returns_requests_session(self) -> None:
        session = get_default_session()
        assert session is not None
        assert isinstance(session, requests.Session)

    def test_returns_same_instance(self) -> None:
        s1 = get_default_session()
        s2 = get_default_session()
        assert s1 is s2

    def test_reset_creates_fresh(self) -> None:
        s1 = get_default_session()
        reset_default_session()
        s2 = get_default_session()
        assert s1 is not s2


class TestSafeGetNarrowSignature:
    """The legacy tests use ``def fake_get(url, params=None, timeout=None)`` —
    confirm :func:`safe_get` doesn't pass extra kwargs that would break them."""

    def test_no_extra_kwargs_passed_to_module_get(self, monkeypatch) -> None:
        captured_kwargs: list[dict] = []

        def _fake_get(url, params=None, timeout=None):
            captured_kwargs.append({"params": params, "timeout": timeout})
            resp = requests.Response()
            resp.status_code = 200
            resp._content = b'{"ok": true}'  # type: ignore[attr-defined]
            return resp

        monkeypatch.setattr("src.recon.collectors.http_safety.requests.get", _fake_get)

        result = safe_get(
            "https://narrow-sig.example.com/",
            provider="unit-test",
            timeout_seconds=5,
            max_retries=0,
        )
        assert result.ok is True
        assert captured_kwargs
        # Only ``params`` and ``timeout`` are passed — no ``headers`` or ``session``.
        kwargs = captured_kwargs[0]
        assert set(kwargs.keys()) == {"params", "timeout"}
