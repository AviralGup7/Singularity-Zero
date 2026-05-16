"""Redis connection management with health checks and in-memory fallback.

Provides a robust Redis client wrapper with connection pooling, automatic
health checks, graceful degradation to in-memory storage when Redis is
unavailable, and support for Lua script execution.
"""

from __future__ import annotations

import json
import threading
import time
from typing import Any

from src.core.logging.trace_logging import get_pipeline_logger
from src.infrastructure.security.encryption import redis_tls_kwargs_from_env

logger = get_pipeline_logger(__name__)


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
        _fallback: In-memory fallback store when Redis is unavailable.
        _use_fallback: Whether to use the in-memory fallback.
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
        self._fallback: dict[str, Any] = {}
        self._fallback_lock = threading.Lock()
        self._use_fallback = False
        self._scripts: dict[str, Any] = {}

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
        if self._use_fallback or self._client is None:
            return self._fallback_command(command, *args, **kwargs)

        try:
            return self._client.execute_command(command, *args, **kwargs)
        except Exception as exc:
            logger.warning("Redis command '%s' failed: %s, using fallback", command, exc)
            self._healthy = False
            self._use_fallback = True
            return self._fallback_command(command, *args, **kwargs)

    def _fallback_command(self, command: str, *args: Any, **kwargs: Any) -> Any:
        """Execute a command against the in-memory fallback store.

        Args:
            command: Command name to emulate.
            *args: Command arguments.
            **kwargs: Command keyword arguments.

        Returns:
            Emulated command result.
        """
        with self._fallback_lock:
            cmd = command.upper()

            if cmd == "GET":
                key = args[0] if args else ""
                if isinstance(key, bytes):
                    key = key.decode("utf-8")
                return self._fallback.get(key)

            if cmd == "SET":
                key = args[0] if args else ""
                value = args[1] if len(args) > 1 else ""
                if isinstance(key, bytes):
                    key = key.decode("utf-8")
                self._fallback[key] = value
                return True

            if cmd == "DELETE" or cmd == "DEL":
                key = args[0] if args else ""
                if isinstance(key, bytes):
                    key = key.decode("utf-8")
                return int(self._fallback.pop(key, None) is not None)

            if cmd == "HSET":
                key = args[0] if args else ""
                if isinstance(key, bytes):
                    key = key.decode("utf-8")
                if key not in self._fallback:
                    self._fallback[key] = {}
                mapping = kwargs.get("mapping", {})
                if args[1:]:
                    rest = list(args[1:])
                    for i in range(0, len(rest) - 1, 2):
                        field = rest[i]
                        value = rest[i + 1] if i + 1 < len(rest) else ""
                        if isinstance(field, bytes):
                            field = field.decode("utf-8")
                        if isinstance(value, bytes):
                            value = value.decode("utf-8")
                        mapping[field] = value
                if isinstance(mapping, dict):
                    for field, value in mapping.items():
                        f = field.decode("utf-8") if isinstance(field, bytes) else field
                        v = value.decode("utf-8") if isinstance(value, bytes) else value
                        self._fallback[key][f] = v
                return len(mapping)

            if cmd == "HGETALL":
                key = args[0] if args else ""
                if isinstance(key, bytes):
                    key = key.decode("utf-8")
                data = self._fallback.get(key, {})
                if isinstance(data, dict):
                    return {
                        k.encode("utf-8") if isinstance(k, str) else k: v.encode("utf-8")
                        if isinstance(v, str)
                        else v
                        for k, v in data.items()
                    }
                return {}

            if cmd == "HGET":
                key = args[0] if args else ""
                field = args[1] if len(args) > 1 else ""
                if isinstance(key, bytes):
                    key = key.decode("utf-8")
                if isinstance(field, bytes):
                    field = field.decode("utf-8")
                data = self._fallback.get(key, {})
                if isinstance(data, dict):
                    val = data.get(field)
                    return val.encode("utf-8") if isinstance(val, str) else val
                return None

            if cmd == "HDEL":
                key = args[0] if args else ""
                if isinstance(key, bytes):
                    key = key.decode("utf-8")
                data = self._fallback.get(key, {})
                if isinstance(data, dict):
                    count = 0
                    for field in args[1:]:
                        f = field.decode("utf-8") if isinstance(field, bytes) else field
                        if f in data:
                            del data[f]
                            count += 1
                    return count
                return 0

            if cmd == "HINCRBY":
                key = args[0] if args else ""
                field = args[1] if len(args) > 1 else ""
                amount = int(args[2]) if len(args) > 2 else 0
                if isinstance(key, bytes):
                    key = key.decode("utf-8")
                if isinstance(field, bytes):
                    field = field.decode("utf-8")
                if key not in self._fallback or not isinstance(self._fallback[key], dict):
                    self._fallback[key] = {}
                current = self._fallback[key].get(field, 0)
                if isinstance(current, bytes):
                    current = current.decode("utf-8")
                try:
                    current_int = int(current)
                except (TypeError, ValueError):
                    current_int = 0
                new_value = current_int + amount
                self._fallback[key][field] = str(new_value)
                return new_value

            if cmd == "EXISTS":
                key = args[0] if args else ""
                if isinstance(key, bytes):
                    key = key.decode("utf-8")
                return int(key in self._fallback)

            if cmd == "EXPIRE":
                return True

            if cmd == "SADD":
                key = args[0] if args else ""
                if isinstance(key, bytes):
                    key = key.decode("utf-8")
                if key not in self._fallback or not isinstance(self._fallback[key], set):
                    self._fallback[key] = set()
                added = 0
                for member in args[1:]:
                    m = member.decode("utf-8") if isinstance(member, bytes) else member
                    if m not in self._fallback[key]:
                        self._fallback[key].add(m)
                        added += 1
                return added

            if cmd == "SREM":
                key = args[0] if args else ""
                if isinstance(key, bytes):
                    key = key.decode("utf-8")
                data = self._fallback.get(key, set())
                if not isinstance(data, set):
                    return 0
                removed = 0
                for member in args[1:]:
                    m = member.decode("utf-8") if isinstance(member, bytes) else member
                    if m in data:
                        data.remove(m)
                        removed += 1
                return removed

            if cmd == "ZADD":
                key = args[0] if args else ""
                if isinstance(key, bytes):
                    key = key.decode("utf-8")
                if key not in self._fallback:
                    self._fallback[key] = {}
                if len(args) >= 3:
                    score = float(args[1])
                    member = args[2]
                    if isinstance(member, bytes):
                        member = member.decode("utf-8")
                    self._fallback[key][member] = score
                return 1

            if cmd == "ZREM":
                key = args[0] if args else ""
                if isinstance(key, bytes):
                    key = key.decode("utf-8")
                data = self._fallback.get(key, {})
                if isinstance(data, dict):
                    count = 0
                    for member in args[1:]:
                        m = member.decode("utf-8") if isinstance(member, bytes) else member
                        if m in data:
                            del data[m]
                            count += 1
                    return count
                return 0

            if cmd == "ZRANGEBYSCORE" or cmd == "ZRANGE":
                key = args[0] if args else ""
                if isinstance(key, bytes):
                    key = key.decode("utf-8")
                data = self._fallback.get(key, {})
                if isinstance(data, dict):
                    items = list(data.items())
                    if cmd == "ZRANGEBYSCORE" and len(args) >= 3:
                        min_raw = args[1]
                        max_raw = args[2]
                        min_score = float(min_raw) if min_raw != "-inf" else float("-inf")
                        max_score = float(max_raw) if max_raw != "+inf" else float("inf")
                        reverse = min_score > max_score
                        if reverse:
                            min_score, max_score = max_score, min_score
                        items = [(m, s) for m, s in items if min_score <= s <= max_score]
                        items.sort(key=lambda x: x[1], reverse=reverse)
                        if len(args) >= 6 and str(args[3]).upper() == "LIMIT":
                            start = int(args[4])
                            count = int(args[5])
                            items = items[start : start + count]
                    elif cmd == "ZRANGE" and len(args) >= 3:
                        start = int(args[1])
                        end = int(args[2])
                        items.sort(key=lambda x: x[1])
                        slice_end = None if end == -1 else end + 1
                        items = items[start:slice_end]
                    else:
                        items.sort(key=lambda x: x[1])
                    return [m.encode("utf-8") if isinstance(m, str) else m for m, _ in items]

            if cmd == "ZREVRANGE":
                key = args[0] if args else ""
                if isinstance(key, bytes):
                    key = key.decode("utf-8")
                start = int(args[1]) if len(args) > 1 else 0
                end = int(args[2]) if len(args) > 2 else -1
                data = self._fallback.get(key, {})
                if isinstance(data, dict):
                    items = sorted(data.items(), key=lambda x: x[1], reverse=True)
                    slice_end = None if end == -1 else end + 1
                    items = items[start:slice_end]
                    return [m.encode("utf-8") if isinstance(m, str) else m for m, _ in items]
                return []

            if cmd == "ZCARD":
                key = args[0] if args else ""
                if isinstance(key, bytes):
                    key = key.decode("utf-8")
                data = self._fallback.get(key, {})
                return len(data) if isinstance(data, dict) else 0

            if cmd == "ZSCORE":
                key = args[0] if args else ""
                member = args[1] if len(args) > 1 else ""
                if isinstance(key, bytes):
                    key = key.decode("utf-8")
                if isinstance(member, bytes):
                    member = member.decode("utf-8")
                data = self._fallback.get(key, {})
                if isinstance(data, dict) and member in data:
                    return str(data[member]).encode("utf-8")
                return None

            if cmd == "LPUSH":
                key = args[0] if args else ""
                if isinstance(key, bytes):
                    key = key.decode("utf-8")
                if key not in self._fallback:
                    self._fallback[key] = []
                for val in args[1:]:
                    v = val.decode("utf-8") if isinstance(val, bytes) else val
                    self._fallback[key].insert(0, v)
                return len(self._fallback[key])

            if cmd == "RPOP":
                key = args[0] if args else ""
                if isinstance(key, bytes):
                    key = key.decode("utf-8")
                data = self._fallback.get(key, [])
                if isinstance(data, list) and data:
                    return data.pop()
                return None

            if cmd == "LLEN":
                key = args[0] if args else ""
                if isinstance(key, bytes):
                    key = key.decode("utf-8")
                data = self._fallback.get(key, [])
                return len(data) if isinstance(data, list) else 0

            if cmd == "EVALSHA":
                return []

            if cmd == "EVAL":
                return []

            if cmd == "SCRIPT":
                return "fallback-script-hash"

            logger.debug("Fallback command not implemented: %s", command)
            return None

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
            return script_hash
        except Exception as exc:
            logger.warning("Failed to register script '%s': %s", name, exc)
            self._scripts[name] = {"hash": f"fallback-{name}", "source": script}
            return self._scripts[name]["hash"]

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

        if self._use_fallback or self._client is None:
            return self._fallback_script_exec(name, keys, args)

        script_info = self._scripts.get(name)
        if script_info is None:
            raise ValueError(f"Script '{name}' not registered")

        try:
            script_obj = script_info.get("object")
            if script_obj is not None:
                return script_obj(keys=keys, args=args)
            return self._client.evalsha(script_info["hash"], len(keys), *(keys + args))
        except Exception as exc:
            logger.warning("Script execution failed for '%s': %s, using fallback", name, exc)
            self._healthy = False
            self._use_fallback = True
            return self._fallback_script_exec(name, keys, args)

    def _fallback_script_exec(self, name: str, keys: list[Any], args: list[Any]) -> Any:
        """Simulate Lua script execution against the in-memory fallback.

        Args:
            name: Script name.
            keys: Redis keys the script would operate on.
            args: Script arguments.

        Returns:
            Simulated result based on script name.
        """
        logger.debug("Fallback script execution: %s keys=%s args=%s", name, keys, args)

        def _as_str(value: Any) -> str:
            if isinstance(value, bytes):
                return value.decode("utf-8")
            return str(value)

        if name == "enqueue" and len(keys) >= 2 and len(args) >= 4:
            job_key = _as_str(keys[0])
            queue_key = _as_str(keys[1])
            priority = float(args[0])
            created_at = float(args[2])
            score = (priority * 10000000000) - created_at

            hash_args_raw = args[3]
            hash_args_list = []
            if isinstance(hash_args_raw, (bytes, str)):
                hash_args_list = json.loads(_as_str(hash_args_raw))
            elif isinstance(hash_args_raw, list):
                hash_args_list = hash_args_raw

            mapping: dict[str, str] = {}
            for idx in range(0, len(hash_args_list) - 1, 2):
                mapping[_as_str(hash_args_list[idx])] = _as_str(hash_args_list[idx + 1])

            self.execute_command("HSET", job_key, mapping=mapping)
            self.execute_command("ZADD", queue_key, score, job_key)
            return [1, _as_str(args[1]).encode("utf-8")]

        if name == "claim_job" and len(keys) >= 3 and len(args) >= 3:
            job_key = _as_str(keys[0])
            queue_key = _as_str(keys[1])
            worker_key = _as_str(keys[2])
            worker_id = _as_str(args[0])
            lease_seconds = float(args[1])
            now_f = float(args[2])

            if self.execute_command("EXISTS", job_key) == 0:
                return [0, b"not_found"]

            state_raw = self.execute_command("HGET", job_key, "state")
            state = _as_str(state_raw) if state_raw is not None else ""
            if state not in ("pending", "retrying"):
                return [0, b"invalid_state", state.encode("utf-8")]

            lease_expires = now_f + lease_seconds
            self.execute_command(
                "HSET",
                job_key,
                "state",
                "claimed",
                "worker_id",
                worker_id,
                "lease_expires_at",
                str(lease_expires),
            )
            self.execute_command("ZREM", queue_key, job_key)
            self.execute_command("SADD", worker_key, job_key)
            return [1, b"claimed"]

        if name == "complete_job" and len(keys) >= 3 and len(args) >= 2:
            job_key = _as_str(keys[0])
            worker_key = _as_str(keys[1])
            metrics_key = _as_str(keys[2])
            result_json = _as_str(args[0])
            now_s = _as_str(args[1])

            if self.execute_command("EXISTS", job_key) == 0:
                return [0]

            self.execute_command(
                "HSET",
                job_key,
                "state",
                "completed",
                "completed_at",
                now_s,
                "result",
                result_json,
                "lease_expires_at",
                "",
                "worker_id",
                "",
            )
            self.execute_command("SREM", worker_key, job_key)
            self.execute_command("HINCRBY", metrics_key, "completed", 1)
            return [1]

        if name == "fail_job" and len(keys) >= 5 and len(args) >= 7:
            job_key = _as_str(keys[0])
            worker_key = _as_str(keys[1])
            queue_key = _as_str(keys[2])
            dlq_key = _as_str(keys[3])
            metrics_key = _as_str(keys[4])

            error_msg = _as_str(args[0])
            retries = int(float(args[1]))
            max_retries = int(float(args[2]))
            now_ff = float(args[3])
            initial = float(args[4])
            multiplier = float(args[5])
            max_delay = float(args[6])

            if self.execute_command("EXISTS", job_key) == 0:
                return [0, b"not_found"]

            self.execute_command("SREM", worker_key, job_key)
            self.execute_command("HSET", job_key, "error", error_msg)

            if retries < max_retries:
                backoff = min(initial * (multiplier**retries), max_delay)
                retry_at = now_ff + backoff
                self.execute_command(
                    "HSET",
                    job_key,
                    "state",
                    "retrying",
                    "worker_id",
                    "",
                    "lease_expires_at",
                    "",
                )
                self.execute_command("ZADD", queue_key, retry_at, job_key)
                self.execute_command("HINCRBY", metrics_key, "retried", 1)
                return [1, b"retrying", str(retry_at).encode("utf-8")]

            self.execute_command(
                "HSET",
                job_key,
                "state",
                "dead_letter",
                "completed_at",
                str(now_ff),
                "worker_id",
                "",
                "lease_expires_at",
                "",
            )
            self.execute_command("ZADD", dlq_key, now_ff, job_key)
            self.execute_command("HINCRBY", metrics_key, "dead_lettered", 1)
            return [2, b"dead_letter"]

        if name == "release_lease" and len(keys) >= 3:
            job_key = _as_str(keys[0])
            worker_key = _as_str(keys[1])
            queue_key = _as_str(keys[2])

            if self.execute_command("EXISTS", job_key) == 0:
                return [0]

            state_raw = self.execute_command("HGET", job_key, "state")
            state = _as_str(state_raw) if state_raw is not None else ""
            if state not in ("claimed", "running"):
                return [0]

            self.execute_command(
                "HSET",
                job_key,
                "state",
                "pending",
                "worker_id",
                "",
                "lease_expires_at",
                "",
            )
            self.execute_command("SREM", worker_key, job_key)
            self.execute_command("ZADD", queue_key, 0, job_key)
            return [1]

        return [0]

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

    def __enter__(self) -> RedisClient:
        """Support context manager entry."""
        return self

    def __exit__(self, *args: Any) -> None:
        """Support context manager exit with cleanup."""
        self.close()
