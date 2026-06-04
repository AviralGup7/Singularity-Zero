"""Tests for the centralized Redis connection configuration."""

from __future__ import annotations

import asyncio
import os
from unittest.mock import patch

import pytest

from src.infrastructure.queue import redis_config
from src.infrastructure.queue.redis_config import (
    DEFAULT_BACKOFF_SECONDS,
    DEFAULT_MAX_RETRIES,
    DEFAULT_RECONNECT_SECONDS,
    DEFAULT_TIMEOUT_SECONDS,
    REDIS_BACKOFF_SECONDS,
    REDIS_MAX_RETRIES,
    REDIS_RECONNECT_SECONDS,
    REDIS_TIMEOUT_SECONDS,
    redis_retry_async,
    redis_retry_sync,
    redis_socket_kwargs,
)


class TestDefaults:
    def test_default_constants_positive(self) -> None:
        assert DEFAULT_TIMEOUT_SECONDS > 0
        assert DEFAULT_MAX_RETRIES >= 0
        assert DEFAULT_BACKOFF_SECONDS > 0
        assert DEFAULT_RECONNECT_SECONDS > 0

    def test_socket_kwargs_uses_timeout(self) -> None:
        kwargs = redis_socket_kwargs()
        assert kwargs["socket_connect_timeout"] == REDIS_TIMEOUT_SECONDS
        assert kwargs["socket_timeout"] == REDIS_TIMEOUT_SECONDS


class TestEnvOverrides:
    def test_env_timeout_override(self) -> None:
        with patch.dict(os.environ, {"REDIS_TIMEOUT_SECONDS": "1.5"}):
            assert redis_config._env_float("REDIS_TIMEOUT_SECONDS", 5.0) == 1.5

    def test_env_retries_override(self) -> None:
        with patch.dict(os.environ, {"REDIS_MAX_RETRIES": "7"}):
            assert redis_config._env_int("REDIS_MAX_RETRIES", 2) == 7

    def test_env_invalid_falls_back(self) -> None:
        with patch.dict(os.environ, {"REDIS_TIMEOUT_SECONDS": "not-a-number"}):
            assert redis_config._env_float("REDIS_TIMEOUT_SECONDS", 5.0) == 5.0

    def test_env_blank_falls_back(self) -> None:
        with patch.dict(os.environ, {"REDIS_TIMEOUT_SECONDS": "   "}):
            assert redis_config._env_float("REDIS_TIMEOUT_SECONDS", 5.0) == 5.0


class TestRedisRetrySync:
    def test_returns_on_first_success(self) -> None:
        calls: list[int] = []

        def op() -> str:
            calls.append(1)
            return "ok"

        assert redis_retry_sync(op) == "ok"
        assert len(calls) == 1

    def test_retries_until_success(self) -> None:
        attempts: list[int] = []

        def op() -> str:
            attempts.append(1)
            if len(attempts) < 3:
                raise ConnectionError("transient")
            return "ok"

        with patch.object(redis_config.time, "sleep") as sleep_mock:
            assert redis_retry_sync(op) == "ok"
        assert len(attempts) == 3
        # sleep should be called between attempts (twice for 3 attempts)
        assert sleep_mock.call_count == 2
        # Exponential backoff doubles the delay
        delays = [c.args[0] for c in sleep_mock.call_args_list]
        assert delays[1] == delays[0] * 2

    def test_raises_after_exhausting_retries(self) -> None:
        attempts: list[int] = []

        def op() -> None:
            attempts.append(1)
            raise ConnectionError("never works")

        with patch.object(redis_config.time, "sleep"):
            with pytest.raises(ConnectionError, match="never works"):
                redis_retry_sync(op)
        # 1 initial + REDIS_MAX_RETRIES retries
        assert len(attempts) == REDIS_MAX_RETRIES + 1


class TestRedisRetryAsync:
    def test_returns_on_first_success(self) -> None:
        calls: list[int] = []

        async def op() -> str:
            calls.append(1)
            return "ok"

        async def runner() -> str:
            return await redis_retry_async(op)

        assert asyncio.run(runner()) == "ok"
        assert len(calls) == 1

    def test_raises_after_exhausting_retries(self) -> None:
        attempts: list[int] = []

        async def op() -> None:
            attempts.append(1)
            raise ConnectionError("async never works")

        async def runner() -> None:
            await redis_retry_async(op)

        with patch.object(redis_config.asyncio, "sleep") as sleep_mock:
            with pytest.raises(ConnectionError, match="async never works"):
                asyncio.run(runner())
        assert sleep_mock.call_count == REDIS_MAX_RETRIES
        assert len(attempts) == REDIS_MAX_RETRIES + 1
