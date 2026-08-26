"""I29 egress context + shared client hooks (F-004)."""

from __future__ import annotations

import asyncio

import httpx
import pytest
import requests

from src.core.contracts.pipeline_runtime import StageOutcome, StageOutput
from src.core.frontier.state import NeuralState
from src.core.frontier.state_authority import SettlementCoordinator, StateAuthority
from src.core.utils import shared_sessions
from src.decision.hunt_budget import HuntBudget, HuntBudgetEnforcer
from src.sandbox.egress_context import (
    assert_url_egress_allowed,
    clear_current_egress_filter,
    ensure_process_http_egress_hooks,
    install_filter_from_scope,
    set_current_egress_filter,
)
from src.sandbox.network_isolation import EgressViolationError, NetworkEgressFilter


def test_metadata_guard_blocks_cloud_imds() -> None:
    clear_current_egress_filter()
    with pytest.raises(EgressViolationError):
        assert_url_egress_allowed("http://169.254.169.254/latest/meta-data/")


def test_strict_scope_filter_blocks_out_of_scope_host() -> None:
    filt = NetworkEgressFilter(allowed_domains=("example.com",), allowed_cidrs=(), strict=True)
    set_current_egress_filter(filt)
    try:
        assert_url_egress_allowed("https://example.com/path")
        with pytest.raises(EgressViolationError):
            assert_url_egress_allowed("https://evil.example.org/")
    finally:
        clear_current_egress_filter()


def test_install_filter_from_scope_entries() -> None:
    filt = install_filter_from_scope(scope_entries=["https://app.target.com", "api.target.com"])
    try:
        assert "app.target.com" in filt.allowed_domains
        assert_url_egress_allowed("https://api.target.com/v1")
        with pytest.raises(EgressViolationError):
            assert_url_egress_allowed("https://169.254.169.254/")
    finally:
        clear_current_egress_filter()


def test_shared_async_client_hook_blocks_metadata() -> None:
    shared_sessions.close_all_async_clients()
    # Reset cleanup flag so new clients can be created after close_all
    shared_sessions._cleanup_done = False  # noqa: SLF001
    clear_current_egress_filter()
    client = shared_sessions.get_async_client()
    hooks = client.event_hooks.get("request") or []
    assert hooks
    req = httpx.Request("GET", "http://169.254.169.254/latest/meta-data/")

    async def _run() -> None:
        for hook in hooks:
            result = hook(req)
            if asyncio.iscoroutine(result):
                await result

    with pytest.raises(EgressViolationError):
        asyncio.run(_run())


async def _fire_request_hooks(client: httpx.AsyncClient | httpx.Client, url: str) -> None:
    req = httpx.Request("GET", url)
    hooks = client.event_hooks.get("request") or []
    assert hooks, "expected I29 request hooks on client"
    for hook in hooks:
        result = hook(req)
        if asyncio.iscoroutine(result):
            await result


def test_raw_httpx_async_client_hook_blocks_imds_and_out_of_scope() -> None:
    """Process-wide patch: raw httpx.AsyncClient() still enforces ContextVar filter."""
    ensure_process_http_egress_hooks()
    filt = NetworkEgressFilter(allowed_domains=("in-scope.test",), allowed_cidrs=(), strict=True)
    set_current_egress_filter(filt)
    try:
        client = httpx.AsyncClient()
        try:
            with pytest.raises(EgressViolationError):
                asyncio.run(_fire_request_hooks(client, "http://169.254.169.254/latest/meta-data/"))
            with pytest.raises(EgressViolationError):
                asyncio.run(_fire_request_hooks(client, "https://evil.example.org/"))
            # In-scope host is allowed by the hook (no raise).
            asyncio.run(_fire_request_hooks(client, "https://in-scope.test/path"))
        finally:
            asyncio.run(client.aclose())
    finally:
        clear_current_egress_filter()


def test_raw_httpx_sync_client_hook_blocks_imds() -> None:
    ensure_process_http_egress_hooks()
    clear_current_egress_filter()  # metadata_guard default
    client = httpx.Client()
    try:
        req = httpx.Request("GET", "http://169.254.169.254/latest/meta-data/")
        hooks = client.event_hooks.get("request") or []
        assert hooks
        with pytest.raises(EgressViolationError):
            for hook in hooks:
                hook(req)
    finally:
        client.close()


def test_raw_requests_session_blocks_imds() -> None:
    """Process-wide Session.request wrap refuses IMDS before connect."""
    ensure_process_http_egress_hooks()
    clear_current_egress_filter()
    session = requests.Session()
    with pytest.raises(EgressViolationError):
        session.request("GET", "http://169.254.169.254/latest/meta-data/")


def test_process_hooks_install_is_idempotent() -> None:
    first = ensure_process_http_egress_hooks()
    second = ensure_process_http_egress_hooks()
    # First call in a fresh interpreter may install; subsequent always False.
    assert second is False
    assert first in {True, False}


def test_stage_settle_zero_findings_releases_budget(tmp_path) -> None:
    """F-004: COMPLETED with zero findings → I28 RELEASE not COMMIT."""
    state = NeuralState()
    authority = StateAuthority(state=state, wal=None)
    enforcer = HuntBudgetEnforcer(HuntBudget(max_requests=10))
    enforcer.reserve_requests(1)
    assert enforcer.reserved_requests == 1
    coordinator = SettlementCoordinator(state_authority=authority, budget_enforcer=enforcer)

    class _Result:
        def __init__(self) -> None:
            self.stage_status: dict = {}
            self.module_metrics: dict = {}
            self._neural_state = state

        def apply_state_delta(self, delta) -> None:
            return None

    class _Ctx:
        run_id = "r-zero"
        result = _Result()
        output_store = None
        execution_ticket = type(
            "T", (), {"budget_reservation_id": "hunt_x_1", "command_id": "cmd"}
        )()

    out = StageOutput(
        stage_name="parameters",
        outcome=StageOutcome.COMPLETED,
        duration_seconds=0.1,
        metrics={},
        state_delta={"parameters": ["id"]},
    )
    res = coordinator.settle_stage_output(_Ctx(), "parameters", out)
    assert res.status == "COMMITTED"
    assert enforcer.reserved_requests == 0
    assert enforcer.consumed_requests == 0
