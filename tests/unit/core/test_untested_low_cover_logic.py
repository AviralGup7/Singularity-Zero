"""Logic bugs found by reading previously untested modules."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from src.core.checkpoint.manager import CheckpointData, LocalCheckpointStore
from src.core.concurrency.structured import CircuitBreaker, RateLimiter
from src.core.persistence.transaction import CircuitBreaker as TxCircuitBreaker
from src.core.persistence.transaction import CircuitBreakerOpenError as TxOpenError
from src.core.persistence.transaction import CircuitState


@pytest.mark.unit
def test_rate_limiter_waits_instead_of_spinning() -> None:
    async def _run() -> None:
        limiter = RateLimiter(rate_per_second=200.0, burst=1)
        await limiter.acquire()
        await asyncio.wait_for(limiter.acquire(), timeout=1.0)

    asyncio.run(_run())


@pytest.mark.unit
def test_local_checkpoint_store_load_latest_after_save(tmp_path: Path) -> None:
    async def _run() -> None:
        store = LocalCheckpointStore(tmp_path)
        saved = CheckpointData(
            run_id="run-a",
            version=1,
            timestamp=1.0,
            stages={"recon": {"ok": True}},
        )
        await store.save(saved)
        loaded = await store.load("run-a")
        assert loaded is not None
        assert loaded.version == 1
        assert loaded.stages["recon"]["ok"] is True

    asyncio.run(_run())


@pytest.mark.unit
def test_structured_circuit_breaker_counts_half_open_calls() -> None:
    async def _ok() -> str:
        return "ok"

    async def _fail() -> None:
        raise RuntimeError("down")

    async def _run() -> None:
        breaker = CircuitBreaker(failure_threshold=1, recovery_timeout=0.01, half_open_max_calls=2)
        with pytest.raises(RuntimeError):
            await breaker.call(_fail)
        assert breaker.state == "open"
        await asyncio.sleep(0.02)
        assert await breaker.call(_ok) == "ok"
        assert breaker.state == "half-open"
        assert breaker._half_open_calls == 1

    asyncio.run(_run())


@pytest.mark.unit
def test_transaction_circuit_breaker_does_not_await_state() -> None:
    async def _ok() -> int:
        return 7

    async def _fail() -> None:
        raise ValueError("no")

    async def _run() -> None:
        breaker = TxCircuitBreaker(failure_threshold=1, recovery_timeout=30.0)
        assert await breaker.call(_ok) == 7
        with pytest.raises(ValueError):
            await breaker.call(_fail)
        assert breaker.state == CircuitState.OPEN
        with pytest.raises(TxOpenError):
            await breaker.call(_ok)

    asyncio.run(_run())
