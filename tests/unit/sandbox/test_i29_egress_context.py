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


def test_raw_socket_connect_blocks_imds_and_out_of_scope() -> None:
    """Raw socket.connect respects ContextVar egress filter."""
    import socket

    from src.sandbox.egress_context import ensure_process_network_egress_hooks

    ensure_process_network_egress_hooks()
    filt = NetworkEgressFilter(allowed_domains=("in-scope.test",), allowed_cidrs=(), strict=True)
    set_current_egress_filter(filt)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            with pytest.raises(EgressViolationError):
                s.connect(("169.254.169.254", 80))
            with pytest.raises(EgressViolationError):
                s.connect(("evil.example.org", 443))
        finally:
            s.close()
    finally:
        clear_current_egress_filter()


def test_asyncio_open_connection_blocks_imds_and_out_of_scope() -> None:
    """asyncio.open_connection respects ContextVar egress filter."""
    from src.sandbox.egress_context import ensure_process_network_egress_hooks

    ensure_process_network_egress_hooks()
    filt = NetworkEgressFilter(allowed_domains=("in-scope.test",), allowed_cidrs=(), strict=True)
    set_current_egress_filter(filt)
    try:
        with pytest.raises(EgressViolationError):
            asyncio.run(asyncio.open_connection("169.254.169.254", 80))
        with pytest.raises(EgressViolationError):
            asyncio.run(asyncio.open_connection("evil.example.org", 443))
    finally:
        clear_current_egress_filter()


def test_transport_primitive_registry() -> None:
    """Every network transport primitive is registered and cataloged."""
    from src.sandbox.egress_context import get_registered_transports, register_transport_primitive

    transports = get_registered_transports()
    assert "httpx" in transports
    assert "requests" in transports
    assert "raw_socket" in transports
    assert "asyncio_stream" in transports
    assert "http2_custom" in transports
    assert "websocket_raw" in transports
    assert "subprocess" in transports
    assert "headless_browser" in transports

    register_transport_primitive("custom_quic", transport_type="quic/udp", enforcement_mechanism="custom_gate")
    assert "custom_quic" in get_registered_transports()


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


def test_i29_raw_thread_propagation_adversarial() -> None:
    """Gap 7: Spawning work in a raw thread or ThreadPoolExecutor still enforces active I29 filter."""
    import threading
    from concurrent.futures import ThreadPoolExecutor

    from src.sandbox.egress_context import (
        assert_egress_allowed,
        clear_current_egress_filter,
        set_current_egress_filter,
    )
    from src.sandbox.network_isolation import EgressViolationError, NetworkEgressFilter

    filt = NetworkEgressFilter(allowed_domains=("in-scope.com",), allowed_cidrs=(), strict=True)
    set_current_egress_filter(filt)
    try:
        thread_error: list[Exception] = []

        def _thread_worker() -> None:
            try:
                assert_egress_allowed("evil.attacker.com")
            except Exception as e:
                thread_error.append(e)

        t = threading.Thread(target=_thread_worker)
        t.start()
        t.join()

        assert len(thread_error) == 1
        assert isinstance(thread_error[0], EgressViolationError)

        # ThreadPoolExecutor execution
        with ThreadPoolExecutor(max_workers=2) as executor:
            fut = executor.submit(assert_egress_allowed, "169.254.169.254")
            with pytest.raises(EgressViolationError):
                fut.result()
    finally:
        clear_current_egress_filter()


def test_i29_hardcoded_metadata_deny_floor_cannot_be_re_enabled() -> None:
    """Gap 8: Hardcoded metadata endpoints cannot be re-enabled even by permissive ScopeToken or 0.0.0.0/0."""
    from src.decision.models import ScopeToken
    from src.sandbox.network_isolation import (
        HARDCODED_METADATA_DENY_LIST,
        NetworkEgressFilter,
    )

    # Even with 0.0.0.0/0 and metadata endpoints in allowed_domains:
    token = ScopeToken(
        scope_hash="hash-123",
        allowed_domains=("169.254.169.254", "metadata.google.internal", "fd00:ec2::254"),
        allowed_cidrs=("0.0.0.0/0", "169.254.0.0/16"),
    )
    filt = NetworkEgressFilter.from_scope_token(token)

    for endpoint in HARDCODED_METADATA_DENY_LIST:
        assert filt.is_destination_allowed(endpoint) is False, f"Metadata {endpoint} must be blocked"

    # Link local IP is blocked
    assert filt.is_destination_allowed("169.254.1.1") is False


def test_i27_claim_deserialization_boundary_64kb_cap() -> None:
    """Gap 9: 64KB bound enforced at the byte/stream deserialization boundary before JSON parse."""
    import io

    from src.core.contracts.execution_request import (
        RAW_CLAIM_MAX_BYTES,
        ClaimTooLargeError,
        RawExecutionClaim,
    )

    # 1. from_bytes rejecting oversized payload before parsing
    oversized_bytes = b"A" * (RAW_CLAIM_MAX_BYTES + 1)
    with pytest.raises(ClaimTooLargeError, match="exceeds deserialization limit"):
        RawExecutionClaim.from_bytes(oversized_bytes)

    # 2. from_stream bounded reading to prevent OOM
    huge_stream = io.BytesIO(b"X" * (RAW_CLAIM_MAX_BYTES * 10))
    with pytest.raises(ClaimTooLargeError, match="aborted to protect worker memory"):
        RawExecutionClaim.from_stream(huge_stream)

    # 3. Valid sized payload succeeds
    import json
    valid_data = {
        "request_id": "req-1",
        "tenant_id": "tenant-1",
        "candidate_id": "cand-1",
        "execution_id": "exec-1",
        "lease_id": "lease-1",
        "epoch": 1,
        "worker_id": "worker-1",
        "outcome": "COMPLETED",
        "duration_seconds": 1.0,
    }
    valid_bytes = json.dumps(valid_data).encode("utf-8")
    claim = RawExecutionClaim.from_bytes(valid_bytes)
    assert claim.request_id == "req-1"
