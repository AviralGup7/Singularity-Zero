"""Tests for circuit-breaker integration in the in-house aggregator."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from src.recon.collectors import aggregator
from src.recon.collectors.health import (
    HEALTH_REGISTRY,
    record_failure,
    reset_health_state,
)
from src.recon.collectors.types import CollectorStatus


def _cfg(**tools_overrides) -> SimpleNamespace:
    tools = {
        "waybackurls": True,
        "commoncrawl": False,
        "katana": False,
        "urlscan": False,
        "otx": False,
    }
    tools.update(tools_overrides)
    return SimpleNamespace(
        tools=tools,
        filters={},
        waybackurls={"timeout_seconds": 30},
        commoncrawl={"timeout_seconds": 30},
        urlscan={"timeout_seconds": 30},
        otx={"timeout_seconds": 30},
        katana={"timeout_seconds": 30},
    )


class TestAggregatorCircuitBreaker:
    def setup_method(self) -> None:
        reset_health_state()

    def teardown_method(self) -> None:
        reset_health_state()

    def test_open_circuit_emits_skipped_meta(self, monkeypatch) -> None:
        # Trip the breaker for "wayback" before the call.
        record_failure("wayback", error="boom")
        record_failure("wayback", error="boom")
        record_failure("wayback", error="boom")

        called = {"flag": False}

        def _fake_collect_for_hosts(*args, **kwargs):
            called["flag"] = True
            return set(), {"status": "ok", "new_urls": 0}

        monkeypatch.setattr(
            aggregator.wayback,
            "collect_for_hosts",
            _fake_collect_for_hosts,
        )

        stage_meta: dict = {}
        aggregator.collect_urls(
            {"https://example.com"},
            ["example.com"],
            _cfg(),
            stage_meta=stage_meta,
        )
        assert called["flag"] is False
        assert "wayback" in stage_meta
        assert str(stage_meta["wayback"]["status"]) == "skipped_circuit_open"

    def test_record_success_keeps_breaker_closed(self, monkeypatch) -> None:
        def _fake_collect_for_hosts(hosts, **_kwargs):
            return {"https://example.com/x"}, {"status": "ok", "new_urls": 1, "duration_seconds": 0.1}

        monkeypatch.setattr(
            aggregator.wayback,
            "collect_for_hosts",
            _fake_collect_for_hosts,
        )

        stage_meta: dict = {}
        aggregator.collect_urls(
            {"https://example.com"},
            ["example.com"],
            _cfg(),
            stage_meta=stage_meta,
        )
        snap = HEALTH_REGISTRY.snapshot()
        assert snap.get("wayback", {}).get("consecutive_failures", 0) == 0
        assert snap.get("wayback", {}).get("total_successes", 0) == 1

    def test_record_failure_increments_counter(self, monkeypatch) -> None:
        def _fake_collect_for_hosts(hosts, **_kwargs):
            raise RuntimeError("upstream down")

        monkeypatch.setattr(
            aggregator.wayback,
            "collect_for_hosts",
            _fake_collect_for_hosts,
        )

        stage_meta: dict = {}
        aggregator.collect_urls(
            {"https://example.com"},
            ["example.com"],
            _cfg(),
            stage_meta=stage_meta,
        )
        # The aggregator catches the exception internally and reports
        # a CollectorMeta with status=error; the health registry should
        # still see a failure.
        snap = HEALTH_REGISTRY.snapshot()
        assert snap.get("wayback", {}).get("total_failures", 0) >= 1
        assert "wayback" in stage_meta
        assert str(stage_meta["wayback"]["status"]) == "error"


class TestAggregatorMetricsSummary:
    def test_summary_includes_circuit_breaker_snapshot(self) -> None:
        reset_health_state()
        record_failure("a")
        stage_meta = {
            "wayback": {"status": "ok", "new_urls": 5, "errors": 0, "duration_seconds": 1.0},
        }
        summary = aggregator.metrics_summary(stage_meta)
        assert "circuit_breaker" in summary
        assert "a" in summary["circuit_breaker"]
        reset_health_state()


class TestSessionKwargsInjection:
    """The session-DI helper should pass ``session=`` only to functions
    whose signature explicitly accepts it.  This keeps the narrow-mock
    test fixtures (``lambda hosts, ...``) working without ``TypeError``."""

    def test_lambda_without_session_kwarg_does_not_receive_session(self) -> None:
        kwargs: dict = {"timeout_seconds": 30}
        func = lambda hosts, timeout_seconds: (set(), {"status": "ok"})
        aggregator._add_session_kwarg_if_supported(func, kwargs)
        assert "session" not in kwargs

    def test_function_with_session_kwarg_receives_session(self) -> None:
        import requests

        def _stub(hosts, session=None):
            return set(), {"status": "ok"}

        kwargs: dict = {"timeout_seconds": 30}
        aggregator._add_session_kwarg_if_supported(_stub, kwargs)
        assert "session" in kwargs
        assert isinstance(kwargs["session"], requests.Session)

    def test_cache_avoids_repeat_inspection(self) -> None:
        def _stub(hosts, session=None):
            return set(), {"status": "ok"}

        # First call populates the cache; second should reuse it.
        aggregator._SESSION_KWARG_SUPPORT_CACHE.pop(id(_stub), None)
        aggregator._add_session_kwarg_if_supported(_stub, {"timeout_seconds": 30})
        assert id(_stub) in aggregator._SESSION_KWARG_SUPPORT_CACHE
        cached = aggregator._SESSION_KWARG_SUPPORT_CACHE[id(_stub)]
        assert cached is True

    def test_existing_session_kwarg_not_overwritten(self) -> None:
        sentinel = object()
        def _stub(hosts, session=None):
            return set(), {"status": "ok"}

        kwargs = {"timeout_seconds": 30, "session": sentinel}
        aggregator._add_session_kwarg_if_supported(_stub, kwargs)
        assert kwargs["session"] is sentinel
