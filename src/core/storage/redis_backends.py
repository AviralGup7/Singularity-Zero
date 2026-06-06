from __future__ import annotations

import json
from typing import Any

try:
    import redis
    from redis.exceptions import RedisError
except ImportError:  # pragma: no cover - exercised only when redis is missing
    redis = None  # type: ignore
    RedisError = Exception  # type: ignore

from src.core.storage.interfaces import CheckpointStore, VersionId


def _parse_version_id(version_id: VersionId) -> int:
    if not isinstance(version_id, str) or not version_id.startswith("v"):
        raise ValueError(f"Invalid checkpoint version id: {version_id!r}")
    suffix = version_id[1:]
    if not suffix.isdigit():
        raise ValueError(f"Invalid checkpoint version id: {version_id!r}")
    return int(suffix)


def _stage_safe_name(stage_name: str) -> str:
    safe = str(stage_name or "").strip() or "unknown"
    if any(c in safe for c in (":", "/", "\\", "..", "\x00")):
        raise ValueError(f"Invalid stage name: {stage_name!r}")
    return safe


class RedisCheckpointStore(CheckpointStore):
    """Redis-backed CheckpointStore.

    Key layout under an optional ``key_prefix`` (default ``"cyber:cp"``)::

        <prefix>:<run_id>:v<n>            JSON string for checkpoint version n
        <prefix>:<run_id>:versions        LIST of version ids in insertion order
        <prefix>:<run_id>:latest          STRING holding the latest version id
        <prefix>:<run_id>:context:<stage> JSON string for the latest context snapshot
        <prefix>:<run_id>:delta:<stage>:<seq:06d>  JSON string for stage delta
        <prefix>:<run_id>:deltas:<stage>  LIST of stage-delta version ids in order

    The store is a thin wrapper around the official ``redis`` client and
    inherits its retry/timeout semantics. All writes are atomic per
    command; the version id is added to the run's version list in the
    same pipeline that writes the JSON payload so the list and the
    payload cannot drift.
    """

    def __init__(
        self,
        redis_url: str,
        *,
        key_prefix: str = "cyber:cp",
        socket_timeout: float = 5.0,
        client: Any | None = None,
    ) -> None:
        if client is not None:
            self._client = client
        else:
            if redis is None:
                raise ImportError(
                    "redis is required for RedisCheckpointStore. "
                    "Install with: pip install redis"
                )
            self._client = redis.from_url(
                redis_url,
                decode_responses=False,
                socket_connect_timeout=socket_timeout,
                socket_timeout=socket_timeout,
                retry_on_timeout=True,
            )
            self._client.ping()
        self._prefix = key_prefix.strip(":") or "cyber:cp"

    @staticmethod
    def _b(value: str) -> bytes:
        return value.encode("utf-8")

    def _versions_key(self, run_id: str) -> str:
        return f"{self._prefix}:{run_id}:versions"

    def list_run_ids(self) -> list[str]:
        run_ids: set[str] = set()
        pattern = f"{self._prefix}:*:latest"
        for key in self._client.scan_iter(match=pattern, count=100):
            decoded = key.decode("utf-8") if isinstance(key, bytes) else str(key)
            suffix = decoded[len(self._prefix) + 1 : -len(":latest")]
            if suffix:
                run_ids.add(suffix)
        return sorted(run_ids)

    def _latest_key(self, run_id: str) -> str:
        return f"{self._prefix}:{run_id}:latest"

    def _version_key(self, run_id: str, version: int) -> str:
        return f"{self._prefix}:{run_id}:v{version}"

    def _context_key(self, run_id: str, stage_name: str) -> str:
        return f"{self._prefix}:{run_id}:context:{_stage_safe_name(stage_name)}"

    def _delta_key(
        self, run_id: str, stage_name: str, sequence: int
    ) -> str:
        return (
            f"{self._prefix}:{run_id}:delta:"
            f"{_stage_safe_name(stage_name)}:{sequence:06d}"
        )

    def _deltas_index_key(self, run_id: str, stage_name: str) -> str:
        return f"{self._prefix}:{run_id}:deltas:{_stage_safe_name(stage_name)}"

    def write(self, run_id: str, version: int, payload: dict[str, Any]) -> VersionId:
        body = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
        version_id = f"v{version}"
        versions_key = self._versions_key(run_id)
        latest_key = self._latest_key(run_id)
        version_key = self._version_key(run_id, version)

        try:
            pipe = self._client.pipeline(transaction=True)
            pipe.rpush(versions_key, version_id)
            pipe.set(version_key, body)
            pipe.set(latest_key, version_id)
            pipe.execute()
        except RedisError:
            raise
        return version_id

    def read_latest(self, run_id: str | None = None) -> dict[str, Any] | None:
        if run_id:
            latest_id = self._client.get(self._latest_key(run_id))
            if latest_id is None:
                return None
            version_id = latest_id.decode("utf-8") if isinstance(latest_id, bytes) else str(latest_id)
            version = _parse_version_id(version_id)
            body = self._client.get(self._version_key(run_id, version))
            if body is None:
                return None
            try:
                return dict(json.loads(body.decode("utf-8")))
            except (UnicodeDecodeError, json.JSONDecodeError):
                return None

        for key in self._client.scan_iter(match=f"{self._prefix}:*:latest", count=100):
            latest_id = self._client.get(key)
            if latest_id is None:
                continue
            run_id_key = key.decode("utf-8") if isinstance(key, bytes) else str(key)
            run_id_match = run_id_key[len(self._prefix) + 1 : -len(":latest")]
            try:
                version = _parse_version_id(
                    latest_id.decode("utf-8")
                    if isinstance(latest_id, bytes)
                    else str(latest_id)
                )
            except ValueError:
                continue
            body = self._client.get(self._version_key(run_id_match, version))
            if body is None:
                continue
            try:
                return dict(json.loads(body.decode("utf-8")))
            except (UnicodeDecodeError, json.JSONDecodeError):
                continue
        return None

    def read_version_by_id(
        self, run_id: str, version_id: VersionId
    ) -> dict[str, Any] | None:
        version = _parse_version_id(version_id)
        body = self._client.get(self._version_key(run_id, version))
        if body is None:
            return None
        try:
            return dict(json.loads(body.decode("utf-8")))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None

    def list_version_ids(self, run_id: str) -> list[VersionId]:
        members = self._client.lrange(self._versions_key(run_id), 0, -1)
        ids: list[VersionId] = []
        for member in members:
            value = member.decode("utf-8") if isinstance(member, bytes) else str(member)
            try:
                _parse_version_id(value)
            except ValueError:
                continue
            ids.append(value)
        return ids

    def delete_version(self, run_id: str, version_id: VersionId) -> None:
        version = _parse_version_id(version_id)
        pipe = self._client.pipeline(transaction=True)
        pipe.lrem(self._versions_key(run_id), 0, version_id)
        pipe.delete(self._version_key(run_id, version))
        pipe.execute()

    def write_context_snapshot(
        self, run_id: str, stage_name: str, payload: dict[str, Any]
    ) -> VersionId:
        body = json.dumps(payload, default=str).encode("utf-8")
        self._client.set(self._context_key(run_id, stage_name), body)
        return f"context:{_stage_safe_name(stage_name)}"

    def read_context_snapshot(
        self, run_id: str, stage_name: str
    ) -> dict[str, Any] | None:
        body = self._client.get(self._context_key(run_id, stage_name))
        if body is None:
            return None
        try:
            return dict(json.loads(body.decode("utf-8")))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None

    def write_stage_delta(
        self,
        run_id: str,
        stage_name: str,
        sequence: int,
        payload: dict[str, Any],
    ) -> VersionId:
        body = json.dumps(payload, default=str).encode("utf-8")
        delta_id = f"delta:{_stage_safe_name(stage_name)}:{sequence:06d}"
        pipe = self._client.pipeline(transaction=True)
        pipe.set(self._delta_key(run_id, stage_name, sequence), body)
        pipe.rpush(self._deltas_index_key(run_id, stage_name), delta_id)
        pipe.execute()
        return delta_id

    def list_stage_deltas(
        self, run_id: str, stage_name: str
    ) -> list[dict[str, Any]]:
        ids = self._client.lrange(self._deltas_index_key(run_id, stage_name), 0, -1)
        results: list[dict[str, Any]] = []
        for member in ids:
            delta_id = member.decode("utf-8") if isinstance(member, bytes) else str(member)
            try:
                _, safe, seq = delta_id.split(":", 2)
                sequence = int(seq)
            except (ValueError, AttributeError):
                continue
            body = self._client.get(self._delta_key(run_id, safe, sequence))
            if body is None:
                continue
            try:
                payload = dict(json.loads(body.decode("utf-8")))
            except (UnicodeDecodeError, json.JSONDecodeError):
                continue
            if isinstance(payload, dict):
                results.append(payload)
        results.sort(key=lambda item: int(item.get("sequence", 0) or 0))
        return results
