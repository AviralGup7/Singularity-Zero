"""Redis command and Lua script emulation layer for RedisClient.

Emulates standard Redis operations and specific queue Lua scripts using
a SQLite/in-memory backend.
"""

from __future__ import annotations

import json
from typing import Any

from src.core.logging.trace_logging import get_pipeline_logger

logger = get_pipeline_logger(__name__)


class FallbackEmulator:
    """Emulates Redis commands and Lua script execution in fallback mode."""

    def __init__(
        self, client: Any, fallback_db: Any, fallback_lock: Any, scripts: dict[str, Any]
    ) -> None:
        """Initialize the emulator.

        Args:
            client: The parent RedisClient instance (for execute_command recursion).
            fallback_db: The FallbackDB helper instance.
            fallback_lock: Thread lock for synchronization.
            scripts: Script registry dictionary.
        """
        self.client = client
        self.fallback_db = fallback_db
        self.fallback_lock = fallback_lock
        self.scripts = scripts
        self._handlers = {
            "GET": self._handle_get,
            "SET": self._handle_set,
            "DELETE": self._handle_del,
            "DEL": self._handle_del,
            "HSET": self._handle_hset,
            "HGETALL": self._handle_hgetall,
            "HGET": self._handle_hget,
            "HDEL": self._handle_hdel,
            "HINCRBY": self._handle_hincrby,
            "EXISTS": self._handle_exists,
            "EXPIRE": self._handle_expire,
            "SADD": self._handle_sadd,
            "SREM": self._handle_srem,
            "SMEMBERS": self._handle_smembers,
            "SCAN": self._handle_scan,
            "ZADD": self._handle_zadd,
            "ZREM": self._handle_zrem,
            "ZRANGEBYSCORE": self._handle_zrangebyscore,
            "ZRANGE": self._handle_zrange,
            "ZREVRANGE": self._handle_zrevrange,
            "ZCARD": self._handle_zcard,
            "ZSCORE": self._handle_zscore,
            "LPUSH": self._handle_lpush,
            "RPOP": self._handle_rpop,
            "LLEN": self._handle_llen,
            "EVALSHA": self._handle_eval,
            "EVAL": self._handle_eval,
            "SCRIPT": self._handle_script,
        }

    def _handle_get(self, *args: Any, **kwargs: Any) -> Any:
        key = args[0] if args else ""
        if isinstance(key, bytes):
            key = key.decode("utf-8")
        _, data = self.fallback_db.db_get(key)
        return data

    def _handle_set(self, *args: Any, **kwargs: Any) -> Any:
        key = args[0] if args else ""
        value = args[1] if len(args) > 1 else ""
        if isinstance(key, bytes):
            key = key.decode("utf-8")
        if isinstance(value, bytes):
            value = value.decode("utf-8")
        self.fallback_db.db_set(key, "string", value)
        return True

    def _handle_del(self, *args: Any, **kwargs: Any) -> Any:
        key = args[0] if args else ""
        if isinstance(key, bytes):
            key = key.decode("utf-8")
        return self.fallback_db.db_del(key)

    def _handle_hset(self, *args: Any, **kwargs: Any) -> Any:
        key = args[0] if args else ""
        if isinstance(key, bytes):
            key = key.decode("utf-8")
        t, data = self.fallback_db.db_get(key)
        if t != "hash" or not isinstance(data, dict):
            data = {}
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
                data[f] = v
        self.fallback_db.db_set(key, "hash", data)
        return len(mapping)

    def _handle_hgetall(self, *args: Any, **kwargs: Any) -> Any:
        key = args[0] if args else ""
        if isinstance(key, bytes):
            key = key.decode("utf-8")
        t, data = self.fallback_db.db_get(key)
        if t == "hash" and isinstance(data, dict):
            return {
                k.encode("utf-8") if isinstance(k, str) else k: v.encode("utf-8")
                if isinstance(v, str)
                else v
                for k, v in data.items()
            }
        return {}

    def _handle_hget(self, *args: Any, **kwargs: Any) -> Any:
        key = args[0] if args else ""
        field = args[1] if len(args) > 1 else ""
        if isinstance(key, bytes):
            key = key.decode("utf-8")
        if isinstance(field, bytes):
            field = field.decode("utf-8")
        t, data = self.fallback_db.db_get(key)
        if t == "hash" and isinstance(data, dict):
            val = data.get(field)
            return val.encode("utf-8") if isinstance(val, str) else val
        return None

    def _handle_hdel(self, *args: Any, **kwargs: Any) -> Any:
        key = args[0] if args else ""
        if isinstance(key, bytes):
            key = key.decode("utf-8")
        t, data = self.fallback_db.db_get(key)
        if t == "hash" and isinstance(data, dict):
            count = 0
            for field in args[1:]:
                f = field.decode("utf-8") if isinstance(field, bytes) else field
                if f in data:
                    del data[f]
                    count += 1
            self.fallback_db.db_set(key, "hash", data)
            return count
        return 0

    def _handle_hincrby(self, *args: Any, **kwargs: Any) -> Any:
        key = args[0] if args else ""
        field = args[1] if len(args) > 1 else ""
        amount = int(args[2]) if len(args) > 2 else 0
        if isinstance(key, bytes):
            key = key.decode("utf-8")
        if isinstance(field, bytes):
            field = field.decode("utf-8")
        t, data = self.fallback_db.db_get(key)
        if t != "hash" or not isinstance(data, dict):
            data = {}
        current = data.get(field, 0)
        if isinstance(current, bytes):
            current = current.decode("utf-8")
        try:
            current_int = int(current)
        except TypeError, ValueError:
            current_int = 0
        new_value = current_int + amount
        data[field] = str(new_value)
        self.fallback_db.db_set(key, "hash", data)
        return new_value

    def _handle_exists(self, *args: Any, **kwargs: Any) -> Any:
        key = args[0] if args else ""
        if isinstance(key, bytes):
            key = key.decode("utf-8")
        t, _ = self.fallback_db.db_get(key)
        return int(t is not None)

    def _handle_expire(self, *args: Any, **kwargs: Any) -> Any:
        return True

    def _handle_sadd(self, *args: Any, **kwargs: Any) -> Any:
        key = args[0] if args else ""
        if isinstance(key, bytes):
            key = key.decode("utf-8")
        t, data = self.fallback_db.db_get(key)
        if t != "set" or not isinstance(data, set):
            data = set()
        added = 0
        for member in args[1:]:
            m = member.decode("utf-8") if isinstance(member, bytes) else member
            if m not in data:
                data.add(m)
                added += 1
        self.fallback_db.db_set(key, "set", data)
        return added

    def _handle_srem(self, *args: Any, **kwargs: Any) -> Any:
        key = args[0] if args else ""
        if isinstance(key, bytes):
            key = key.decode("utf-8")
        t, data = self.fallback_db.db_get(key)
        if t != "set" or not isinstance(data, set):
            return 0
        removed = 0
        for member in args[1:]:
            m = member.decode("utf-8") if isinstance(member, bytes) else member
            if m in data:
                data.remove(m)
                removed += 1
        self.fallback_db.db_set(key, "set", data)
        return removed

    def _handle_smembers(self, *args: Any, **kwargs: Any) -> Any:
        key = args[0] if args else ""
        if isinstance(key, bytes):
            key = key.decode("utf-8")
        t, data = self.fallback_db.db_get(key)
        if t == "set" and isinstance(data, set):
            return [m.encode("utf-8") if isinstance(m, str) else m for m in data]
        return []

    def _handle_scan(self, *args: Any, **kwargs: Any) -> Any:
        pattern = "*"
        if "MATCH" in [str(arg).upper() for arg in args]:
            upper_args = [str(arg).upper() for arg in args]
            pattern = str(args[upper_args.index("MATCH") + 1])
        import fnmatch

        all_keys = self.fallback_db.db_scan()
        keys = [key.encode("utf-8") for key in all_keys if fnmatch.fnmatch(str(key), pattern)]
        return 0, keys

    def _handle_zadd(self, *args: Any, **kwargs: Any) -> Any:
        key = args[0] if args else ""
        if isinstance(key, bytes):
            key = key.decode("utf-8")
        t, data = self.fallback_db.db_get(key)
        if t != "zset" or not isinstance(data, dict):
            data = {}
        if len(args) >= 3:
            score = float(args[1])
            member = args[2]
            if isinstance(member, bytes):
                member = member.decode("utf-8")
            data[member] = score
        self.fallback_db.db_set(key, "zset", data)
        return 1

    def _handle_zrem(self, *args: Any, **kwargs: Any) -> Any:
        key = args[0] if args else ""
        if isinstance(key, bytes):
            key = key.decode("utf-8")
        t, data = self.fallback_db.db_get(key)
        if t == "zset" and isinstance(data, dict):
            count = 0
            for member in args[1:]:
                m = member.decode("utf-8") if isinstance(member, bytes) else member
                if m in data:
                    del data[m]
                    count += 1
            self.fallback_db.db_set(key, "zset", data)
            return count
        return 0

    def _handle_zrangebyscore(self, *args: Any, **kwargs: Any) -> Any:
        key = args[0] if args else ""
        if isinstance(key, bytes):
            key = key.decode("utf-8")
        t, data = self.fallback_db.db_get(key)
        if t == "zset" and isinstance(data, dict):
            items = list(data.items())
            if len(args) >= 3:
                min_raw = args[1]
                max_raw = args[2]
                if isinstance(min_raw, bytes):
                    min_raw = min_raw.decode("utf-8")
                if isinstance(max_raw, bytes):
                    max_raw = max_raw.decode("utf-8")
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
            else:
                items.sort(key=lambda x: x[1])
            return [m.encode("utf-8") if isinstance(m, str) else m for m, _ in items]
        return []

    def _handle_zrange(self, *args: Any, **kwargs: Any) -> Any:
        key = args[0] if args else ""
        if isinstance(key, bytes):
            key = key.decode("utf-8")
        t, data = self.fallback_db.db_get(key)
        if t == "zset" and isinstance(data, dict):
            items = list(data.items())
            if len(args) >= 3:
                start = int(args[1])
                end = int(args[2])
                items.sort(key=lambda x: x[1])
                slice_end = None if end == -1 else end + 1
                items = items[start:slice_end]
            else:
                items.sort(key=lambda x: x[1])
            return [m.encode("utf-8") if isinstance(m, str) else m for m, _ in items]
        return []

    def _handle_zrevrange(self, *args: Any, **kwargs: Any) -> Any:
        key = args[0] if args else ""
        if isinstance(key, bytes):
            key = key.decode("utf-8")
        start = int(args[1]) if len(args) > 1 else 0
        end = int(args[2]) if len(args) > 2 else -1
        t, data = self.fallback_db.db_get(key)
        if t == "zset" and isinstance(data, dict):
            items = sorted(data.items(), key=lambda x: x[1], reverse=True)
            slice_end = None if end == -1 else end + 1
            items = items[start:slice_end]
            return [m.encode("utf-8") if isinstance(m, str) else m for m, _ in items]
        return []

    def _handle_zcard(self, *args: Any, **kwargs: Any) -> Any:
        key = args[0] if args else ""
        if isinstance(key, bytes):
            key = key.decode("utf-8")
        t, data = self.fallback_db.db_get(key)
        return len(data) if t == "zset" and isinstance(data, dict) else 0

    def _handle_zscore(self, *args: Any, **kwargs: Any) -> Any:
        key = args[0] if args else ""
        member = args[1] if len(args) > 1 else ""
        if isinstance(key, bytes):
            key = key.decode("utf-8")
        if isinstance(member, bytes):
            member = member.decode("utf-8")
        t, data = self.fallback_db.db_get(key)
        if t == "zset" and isinstance(data, dict) and member in data:
            return str(data[member]).encode("utf-8")
        return None

    def _handle_lpush(self, *args: Any, **kwargs: Any) -> Any:
        key = args[0] if args else ""
        if isinstance(key, bytes):
            key = key.decode("utf-8")
        t, data = self.fallback_db.db_get(key)
        if t != "list" or not isinstance(data, list):
            data = []
        for val in args[1:]:
            v = val.decode("utf-8") if isinstance(val, bytes) else val
            data.insert(0, v)
        self.fallback_db.db_set(key, "list", data)
        return len(data)

    def _handle_rpop(self, *args: Any, **kwargs: Any) -> Any:
        key = args[0] if args else ""
        if isinstance(key, bytes):
            key = key.decode("utf-8")
        t, data = self.fallback_db.db_get(key)
        if t == "list" and isinstance(data, list) and data:
            val = data.pop()
            self.fallback_db.db_set(key, "list", data)
            return val.encode("utf-8") if isinstance(val, str) else val
        return None

    def _handle_llen(self, *args: Any, **kwargs: Any) -> Any:
        key = args[0] if args else ""
        if isinstance(key, bytes):
            key = key.decode("utf-8")
        t, data = self.fallback_db.db_get(key)
        return len(data) if t == "list" and isinstance(data, list) else 0

    def _handle_eval(self, *args: Any, **kwargs: Any) -> Any:
        return []

    def _handle_script(self, *args: Any, **kwargs: Any) -> Any:
        return "fallback-script-hash"

    def fallback_command(self, command: str, *args: Any, **kwargs: Any) -> Any:
        """Execute a command against the SQLite fallback store."""
        with self.fallback_lock:
            cmd = command.upper()
            handler = self._handlers.get(cmd)
            if handler is not None:
                return handler(*args, **kwargs)
            logger.debug("Fallback command not implemented: %s", command)
            return None

    def fallback_script_exec(self, name: str, keys: list[Any], args: list[Any]) -> Any:
        """Simulate Lua script execution against the fallback database."""
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
            score = float(args[4]) if len(args) > 4 else (priority * 10000000000) - created_at

            hash_args_raw = args[3]
            hash_args_list = []
            if isinstance(hash_args_raw, (bytes, str)):
                hash_args_list = json.loads(_as_str(hash_args_raw))
            elif isinstance(hash_args_raw, list):
                hash_args_list = hash_args_raw

            mapping: dict[str, str] = {}
            for idx in range(0, len(hash_args_list) - 1, 2):
                mapping[_as_str(hash_args_list[idx])] = _as_str(hash_args_list[idx + 1])

            self.client.execute_command("HSET", job_key, mapping=mapping)
            self.client.execute_command("ZADD", queue_key, score, job_key)
            return [1, _as_str(args[1]).encode("utf-8")]

        if name == "claim_job" and len(keys) >= 3 and len(args) >= 3:
            job_key = _as_str(keys[0])
            queue_key = _as_str(keys[1])
            worker_key = _as_str(keys[2])
            worker_id = _as_str(args[0])
            lease_seconds = float(args[1])
            now_f = float(args[2])

            if self.client.execute_command("EXISTS", job_key) == 0:
                return [0, b"not_found"]

            state_raw = self.client.execute_command("HGET", job_key, "state")
            state = _as_str(state_raw) if state_raw is not None else ""
            if state not in ("pending", "retrying"):
                return [0, b"invalid_state", state.encode("utf-8")]

            lease_expires = now_f + lease_seconds
            self.client.execute_command(
                "HSET",
                job_key,
                "state",
                "claimed",
                "worker_id",
                worker_id,
                "lease_expires_at",
                str(lease_expires),
            )
            self.client.execute_command("ZREM", queue_key, job_key)
            self.client.execute_command("SADD", worker_key, job_key)
            return [1, b"claimed"]

        if name == "complete_job" and len(keys) >= 3 and len(args) >= 2:
            job_key = _as_str(keys[0])
            worker_key = _as_str(keys[1])
            metrics_key = _as_str(keys[2])
            result_json = _as_str(args[0])
            now_s = _as_str(args[1])

            if self.client.execute_command("EXISTS", job_key) == 0:
                return [0]

            self.client.execute_command(
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
            self.client.execute_command("SREM", worker_key, job_key)
            self.client.execute_command("HINCRBY", metrics_key, "completed", 1)
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

            if self.client.execute_command("EXISTS", job_key) == 0:
                return [0, b"not_found"]

            self.client.execute_command("SREM", worker_key, job_key)
            self.client.execute_command("HSET", job_key, "error", error_msg)

            if retries < max_retries:
                backoff = min(initial * (multiplier**retries), max_delay)
                retry_at = now_ff + backoff
                bid_raw = self.client.execute_command("HGET", job_key, "bid_score")
                try:
                    queue_score = float(_as_str(bid_raw)) if bid_raw is not None else retry_at
                except TypeError, ValueError:
                    queue_score = retry_at
                self.client.execute_command(
                    "HSET",
                    job_key,
                    "state",
                    "retrying",
                    "worker_id",
                    "",
                    "lease_expires_at",
                    "",
                )
                self.client.execute_command("ZADD", queue_key, queue_score, job_key)
                self.client.execute_command("HINCRBY", metrics_key, "retried", 1)
                return [1, b"retrying", str(retry_at).encode("utf-8")]

            self.client.execute_command(
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
            self.client.execute_command("ZADD", dlq_key, now_ff, job_key)
            self.client.execute_command("HINCRBY", metrics_key, "dead_lettered", 1)
            return [2, b"dead_letter"]

        if name == "release_lease" and len(keys) >= 3:
            job_key = _as_str(keys[0])
            worker_key = _as_str(keys[1])
            queue_key = _as_str(keys[2])

            if self.client.execute_command("EXISTS", job_key) == 0:
                return [0]

            state_raw = self.client.execute_command("HGET", job_key, "state")
            state = _as_str(state_raw) if state_raw is not None else ""
            if state not in ("claimed", "running"):
                return [0]

            self.client.execute_command(
                "HSET",
                job_key,
                "state",
                "pending",
                "worker_id",
                "",
                "lease_expires_at",
                "",
            )
            self.client.execute_command("SREM", worker_key, job_key)
            bid_raw = self.client.execute_command("HGET", job_key, "bid_score")
            try:
                queue_score = float(_as_str(bid_raw)) if bid_raw is not None else 0.0
            except TypeError, ValueError:
                queue_score = 0.0
            self.client.execute_command("ZADD", queue_key, queue_score, job_key)
            return [1]

        return [0]
