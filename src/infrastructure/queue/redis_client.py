"""Redis connection management with health checks and in-memory fallback.

Provides a robust Redis client wrapper with connection pooling, automatic
health checks, graceful degradation to in-memory storage when Redis is
unavailable, and support for Lua script execution.
"""

from __future__ import annotations

import os
import threading
import time
from typing import Any, cast

from src.core.logging.trace_logging import get_pipeline_logger
from src.core.security.circuit_breaker import CircuitBreaker
from src.core.tenant_context import TenantContext
from src.infrastructure.queue.fallback_db import FallbackDB
from src.infrastructure.queue.fallback_emulator import FallbackEmulator
from src.infrastructure.security.encryption import redis_tls_kwargs_from_env

logger = get_pipeline_logger(__name__)

DEFAULT_REDIS_TIMEOUT_SECONDS = 5
DEFAULT_REDIS_RETRIES = 2
DEFAULT_REDIS_BACKOFF_SECONDS = 0.1
DEFAULT_RECONNECT_INTERVAL_SECONDS = 30.0


class RedisClient:
    """Manages Redis connections with pooling, health checks, and fallback.

    This class wraps the Redis client library with connection pooling,
    periodic health checks, and automatic fallback to an in-memory store
    when Redis is unavailable. It is thread-safe and suitable for use
    in multi-threaded and async contexts.

    Attributes:
        url: Redis connection URL.
        db: Redis database number.
        max_connections: Maximum connections in the pool.
        _pool: Redis connection pool instance.
        _client: Active Redis client instance.
        _healthy: Whether the Redis connection is currently healthy.
        _last_check: Timestamp of the last health check.
        _lock: Thread lock for health check synchronization.
        _fallback_db: Fallback SQLite database instance.
        _fallback_emulator: Emulation layer for Redis commands/scripts.
        _use_fallback: Whether to use the fallback store.
    """

    def __init__(
        self,
        url: str | None = None,
        db: int = 0,
        max_connections: int = 20,
    ) -> None:
        """Initialize the Redis client.

        Args:
            url: Redis connection URL (e.g., "redis://localhost:6379").
                 If None or empty, falls back to in-memory mode.
            db: Redis database number (0-15).
            max_connections: Maximum connections in the connection pool.
        """
        self.url = url
        self.db = db
        self.max_connections = max_connections
        self._pool: Any = None
        self._client: Any = None
        self._healthy = False
        self._last_check = 0.0
        self._lock = threading.Lock()
        self._fallback_lock = threading.Lock()
        self._use_fallback = False
        self._fallback_since = 0.0
        self._reconnect_interval = DEFAULT_RECONNECT_INTERVAL_SECONDS
        self._scripts: dict[str, Any] = {}
        self._breaker = CircuitBreaker("redis-client", failure_threshold=3, recovery_timeout=10.0)

        db_dir = os.path.join("output")
        os.makedirs(db_dir, exist_ok=True)
        self._db_path = os.path.join(db_dir, "local_queue.db")

        # Initialize modular fallback DB and emulator
        self._fallback_db = FallbackDB(self._db_path)
        self._fallback_emulator = FallbackEmulator(
            client=self,
            fallback_db=self._fallback_db,
            fallback_lock=self._fallback_lock,
            scripts=self._scripts,
        )

        if not url:
            logger.info("No Redis URL provided, using in-memory fallback")
            self._use_fallback = True
            return

        self._initialize()

    def _initialize(self) -> None:
        """Initialize the Redis connection pool and client."""
        if not self.url:
            self._use_fallback = True
            return

        try:
            import redis
        except ImportError:
            logger.warning("redis package not installed, using in-memory fallback")
            self._use_fallback = True
            return

        try:
            self._pool = redis.ConnectionPool.from_url(
                self.url,
                db=self.db,
                max_connections=self.max_connections,
                decode_responses=False,
                socket_timeout=5,
                socket_connect_timeout=5,
                retry_on_timeout=True,
                socket_keepalive=True,
                health_check_interval=30,
                **redis_tls_kwargs_from_env(),
            )
            self._client = redis.Redis(connection_pool=self._pool)
            self._check_health()
            if not self._healthy:
                logger.warning("Redis connection failed on init, using in-memory fallback")
                self._use_fallback = True
        except Exception as exc:
            logger.warning("Redis initialization error: %s, using in-memory fallback", exc)
            self._use_fallback = True

    def _check_health(self) -> bool:
        """Perform a health check on the Redis connection.

        Returns:
            True if Redis is reachable and responding.
        """
        if self._use_fallback or self._client is None:
            return False

        try:
            result = self._client.ping()
            was_unhealthy = not self._healthy
            self._healthy = bool(result)
            self._last_check = time.time()

            if was_unhealthy and self._healthy:
                logger.info("Redis connection restored")
            elif not self._healthy:
                logger.warning("Redis health check failed")

            return self._healthy
        except Exception as exc:
            self._healthy = False
            self._last_check = time.time()
            logger.debug("Redis ping failed: %s", exc)
            return False

    @property
    def is_healthy(self) -> bool:
        """Check if the Redis connection is currently healthy.

        Performs a health check if the last check was more than 10 seconds ago.

        Returns:
            True if Redis is healthy or if using in-memory fallback.
        """
        with self._lock:
            if self._use_fallback:
                return True

            now = time.time()
            if now - self._last_check > 10:
                self._check_health()

            if not self._healthy:
                self._use_fallback = True
                logger.warning("Switching to in-memory fallback due to Redis failure")

            return self._healthy or self._use_fallback

    @property
    def client(self) -> Any:
        """Get the underlying Redis client instance.

        Returns:
            Redis client instance, or None if using fallback.
        """
        if self._use_fallback or self._client is None:
            return None
        return self._client

    def execute_command(self, command: str, *args: Any, **kwargs: Any) -> Any:
        """Execute a Redis command with automatic fallback.

        Args:
            command: Redis command name (e.g., "GET", "SET", "HSET").
            *args: Command arguments.
            **kwargs: Command keyword arguments.

        Returns:
            Command result, or fallback implementation result.
        """
        tenant_id = TenantContext.get_current_tenant()
        if tenant_id and len(args) > 0:
            key = args[0]
            if isinstance(key, str):
                if not key.startswith(f"{tenant_id}:"):
                    args = (f"{tenant_id}:{key}",) + args[1:]
            elif isinstance(key, bytes):
                prefix_bytes = f"{tenant_id}:".encode()
                if not key.startswith(prefix_bytes):
                    args = (prefix_bytes + key,) + args[1:]

        if self._use_fallback or self._client is None:
            self._maybe_recover()
        if self._use_fallback or self._client is None:
            return self._fallback_emulator.fallback_command(command, *args, **kwargs)

        try:
            return self._breaker.call(
                self._with_retries,
                lambda: self._client.execute_command(command, *args, **kwargs),
            )
        except Exception as exc:
            logger.warning("Redis command '%s' failed: %s, using fallback", command, exc)
            self._enter_fallback()
            return self._fallback_emulator.fallback_command(command, *args, **kwargs)

    def execute_batch(self, commands: list[tuple[str, list[Any]]]) -> list[Any]:
        """Execute multiple Redis commands in a single pipelined batch with fallback.

        Args:
            commands: A list of tuples containing (command_name, arguments_list).

        Returns:
            A list of execution results corresponding to the input commands.
        """
        tenant_id = TenantContext.get_current_tenant()
        processed_commands = []
        for cmd_name, args in commands:
            args = list(args)
            if tenant_id and len(args) > 0:
                key = args[0]
                if isinstance(key, str):
                    if not key.startswith(f"{tenant_id}:"):
                        args[0] = f"{tenant_id}:{key}"
                elif isinstance(key, bytes):
                    prefix_bytes = f"{tenant_id}:".encode()
                    if not key.startswith(prefix_bytes):
                        args[0] = prefix_bytes + key
            processed_commands.append((cmd_name, args))

        if self._use_fallback or self._client is None:
            self._maybe_recover()
        if self._use_fallback or self._client is None:
            return [
                self._fallback_emulator.fallback_command(cmd_name, *args)
                for cmd_name, args in processed_commands
            ]

        try:
            def run_pipeline() -> list[Any]:
                pipe = self._client.pipeline()
                for cmd_name, args in processed_commands:
                    pipe.execute_command(cmd_name, *args)
                return pipe.execute()

            return self._breaker.call(self._with_retries, run_pipeline)
        except Exception as exc:
            logger.warning("Pipelined execution failed: %s, using fallback", exc)
            self._enter_fallback()
            return [
                self._fallback_emulator.fallback_command(cmd_name, *args)
                for cmd_name, args in processed_commands
            ]

    def register_script(self, name: str, script: str) -> str:
        """Register a Lua script for atomic Redis operations.

        Args:
            name: Human-readable name for the script.
            script: Lua script source code.

        Returns:
            Script SHA hash for use with EVALSHA.
        """
        if self._use_fallback or self._client is None:
            script_hash = f"fallback-{name}"
            self._scripts[name] = {"hash": script_hash, "source": script}
            return script_hash

        try:
            script_obj = self._client.register_script(script)
            script_hash = script_obj.sha
            self._scripts[name] = {"hash": script_hash, "source": script, "object": script_obj}
            return cast(str, script_hash)
        except Exception as exc:
            logger.warning("Failed to register script '%s': %s", name, exc)
            fallback_hash = f"fallback-{name}"
            self._scripts[name] = {"hash": fallback_hash, "source": script}
            return fallback_hash

    def execute_script(
        self, name: str, keys: list[Any] | None = None, args: list[Any] | None = None
    ) -> Any:
        """Execute a registered Lua script.

        Args:
            name: Name of the registered script.
            keys: List of Redis keys to pass to the script.
            args: List of arguments to pass to the script.

        Returns:
            Script execution result.
        """
        keys = keys or []
        args = args or []

        tenant_id = TenantContext.get_current_tenant()
        if tenant_id:
            prefixed_keys: list[Any] = []
            for k in keys:
                if isinstance(k, str):
                    if not k.startswith(f"{tenant_id}:"):
                        prefixed_keys.append(f"{tenant_id}:{k}")
                    else:
                        prefixed_keys.append(k)
                elif isinstance(k, bytes):
                    prefix_bytes = f"{tenant_id}:".encode()
                    if not k.startswith(prefix_bytes):
                        prefixed_keys.append(prefix_bytes + k)
                    else:
                        prefixed_keys.append(k)
                else:
                    prefixed_keys.append(k)
            keys = prefixed_keys

        if self._use_fallback or self._client is None:
            self._maybe_recover()
        if self._use_fallback or self._client is None:
            return self._fallback_emulator.fallback_script_exec(name, keys, args)

        script_info = self._scripts.get(name)
        if script_info is None:
            raise ValueError(f"Script '{name}' not registered")

        try:

            def run_script() -> Any:
                script_obj = script_info.get("object")
                if script_obj is not None:
                    return script_obj(keys=keys, args=args)
                return self._client.evalsha(script_info["hash"], len(keys), *(keys + args))

            return self._breaker.call(self._with_retries, run_script)
        except Exception as exc:
            logger.warning("Script execution failed for '%s': %s, using fallback", name, exc)
            self._enter_fallback()
            return self._fallback_emulator.fallback_script_exec(name, keys, args)

    def close(self) -> None:
        """Close the Redis connection pool and release resources."""
        if self._pool is not None:
            try:
                self._pool.disconnect()
            except Exception as exc:
                logger.debug("Redis pool disconnect failed: %s", exc)
            self._pool = None
            self._client = None
            self._healthy = False
        try:
            self._fallback_db.close()
        except Exception as exc:
            logger.debug("Fallback DB close failed: %s", exc)

    def __enter__(self) -> RedisClient:
        """Support context manager entry."""
        return self

    def __exit__(self, *args: Any) -> None:
        """Support context manager exit with cleanup."""
        self.close()

    def _with_retries(self, fn: Any) -> Any:
        delay = DEFAULT_REDIS_BACKOFF_SECONDS
        last_error: Exception | None = None
        for attempt in range(DEFAULT_REDIS_RETRIES + 1):
            try:
                return fn()
            except Exception as exc:
                last_error = exc
                if attempt >= DEFAULT_REDIS_RETRIES:
                    break
                time.sleep(delay)
                delay *= 2
        raise last_error or RuntimeError("Redis operation failed")

    def _enter_fallback(self) -> None:
        self._healthy = False
        self._use_fallback = True
        self._fallback_since = time.time()

    def _maybe_recover(self) -> None:
        if not self.url or not self._use_fallback:
            return
        if time.time() - self._fallback_since < self._reconnect_interval:
            return
        with self._lock:
            if not self._use_fallback:
                return
            self._use_fallback = False
            self._initialize()
            if self._healthy:
                logger.info("Redis recovered; leaving SQLite fallback mode")
            else:
                self._enter_fallback()
