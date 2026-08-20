from __future__ import annotations

import abc
import asyncio
import hashlib
import json
import logging
import os
import re
import secrets
import time
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any, TypeVar

from src.core.checkpoint.health import (
    DEFAULT_STALE_AFTER_SECONDS,
    CheckpointFencedError,
    CheckpointHealth,
    FenceState,
    assert_writable_fence,
    inspect_remote_fence,
    is_checkpoint_stale,
)

logger = logging.getLogger(__name__)

_SAFE_RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")

T = TypeVar("T")


def _atomic_write_text(path: Path, content: str) -> None:
    """Write ``content`` to ``path`` and fsync. Caller then ``os.replace``s."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(content)
        handle.flush()
        try:
            os.fsync(handle.fileno())
        except OSError:
            pass


@dataclass
class CheckpointData:
    """Immutable checkpoint snapshot."""

    run_id: str
    version: int
    timestamp: float
    stages: dict[str, Any] = field(default_factory=dict)
    artifacts: dict[str, str] = field(default_factory=dict)  # key -> checksum
    metadata: dict = field(default_factory=dict)

    def to_json(self) -> str:
        return json.dumps(self.__dict__, sort_keys=True)

    @classmethod
    def from_json(cls, data: str) -> CheckpointData:
        try:
            parsed = json.loads(data)
        except json.JSONDecodeError as exc:
            raise ValueError("corrupt checkpoint json") from exc
        if not isinstance(parsed, dict):
            raise ValueError("corrupt checkpoint json")
        allowed = {item.name for item in fields(cls)}
        return cls(**{key: value for key, value in parsed.items() if key in allowed})

    def checksum(self) -> str:
        return hashlib.sha256(self.to_json().encode()).hexdigest()


class CheckpointStore(abc.ABC):
    """Abstract checkpoint storage."""

    @abc.abstractmethod
    async def save(self, data: CheckpointData) -> str:
        """Save checkpoint, return version_id."""
        ...

    @abc.abstractmethod
    async def load(self, run_id: str, version: int | None = None) -> CheckpointData | None:
        """Load checkpoint. If version is None, load latest."""
        ...

    @abc.abstractmethod
    async def list_versions(self, run_id: str) -> list[int]:
        """List available checkpoint versions."""
        ...

    @abc.abstractmethod
    async def delete(self, run_id: str, version: int) -> bool:
        """Delete a specific checkpoint version."""
        ...

    @abc.abstractmethod
    async def prune(self, run_id: str, keep_last: int) -> int:
        """Delete old checkpoints, keep last N. Return count deleted."""
        ...


@dataclass
class CheckpointManager:
    """High-level checkpoint management."""

    store: Any  # CheckpointStore
    run_id: str
    _current: CheckpointData | None = None
    _version: int = 0
    _dirty: bool = False
    _auto_save_task: Any = None
    retry_attempts: int = 3
    retry_base_delay: float = 0.05
    stale_after_seconds: float = DEFAULT_STALE_AFTER_SECONDS
    fence_token: str = field(default_factory=lambda: secrets.token_hex(8))
    _fence: FenceState = field(
        default_factory=lambda: FenceState(token=""),
        init=False,
        repr=False,
        compare=False,
    )
    _health: CheckpointHealth = field(
        default_factory=CheckpointHealth, init=False, repr=False, compare=False
    )

    def __post_init__(self) -> None:
        self._fence = FenceState(token=self.fence_token)
        self._health.fence_token = self.fence_token

    @property
    def health(self) -> CheckpointHealth:
        self._health.stale = self.is_stale()
        self._health.fenced = self._fence.fenced
        self._health.fence_token = self._fence.token
        return self._health

    def is_stale(self, *, now: float | None = None) -> bool:
        last = self._health.last_success_at
        if last is None and self._current is not None:
            last = self._current.timestamp
        return is_checkpoint_stale(
            last,
            now=now,
            max_age_seconds=self.stale_after_seconds,
            dirty=self._dirty,
        )

    async def load(self) -> CheckpointData | None:
        """Load latest checkpoint."""
        data = await self.store.load(self.run_id)
        if data:
            self._current = data
            self._version = data.version
            _token, generation = inspect_remote_fence(data.metadata)
            if generation:
                self._fence.generation = max(self._fence.generation, generation)
        return data

    def get_stage(self, name: str) -> dict | None:
        return self._current.stages.get(name) if self._current else None

    def set_stage(self, name: str, data: dict) -> None:
        if not self._current:
            self._current = CheckpointData(run_id=self.run_id, version=0, timestamp=time.time())
        self._current.stages[name] = data
        self._dirty = True

    def set_artifact(self, key: str, checksum: str) -> None:
        if not self._current:
            self._current = CheckpointData(run_id=self.run_id, version=0, timestamp=time.time())
        self._current.artifacts[key] = checksum
        self._dirty = True

    async def save(self, force: bool = False) -> str | None:
        """Save checkpoint if dirty or forced.

        I/O failures are retried with exponential backoff. Version is
        incremented once per dirty cycle so a failed attempt does not
        skip a generation on retry. Health is updated on every outcome.
        The loop in ``auto_save`` keeps running even when this raises.
        """
        if not self._dirty and not force:
            return None
        if not self._current:
            return None
        if self._fence.fenced:
            self._health.record_failure("fenced", fenced=True)
            raise CheckpointFencedError(f"run {self.run_id} is fenced")

        await self._check_fence()

        attempts = max(1, int(self.retry_attempts))
        delay = max(0.0, float(self.retry_base_delay))
        last_error: Exception | None = None
        started = time.perf_counter()
        versioned = False

        for attempt in range(1, attempts + 1):
            try:
                if not versioned:
                    self._version += 1
                    self._current.version = self._version
                    self._current.timestamp = time.time()
                    self._stamp_fence()
                    versioned = True
                version_id = await self.store.save(self._current)
                self._dirty = False
                duration_ms = (time.perf_counter() - started) * 1000.0
                self._health.record_success(duration_ms)
                return version_id
            except CheckpointFencedError:
                self._health.record_failure("fenced", fenced=True)
                raise
            except Exception as exc:
                last_error = exc
                self._health.record_failure(str(exc))
                logger.warning(
                    "Checkpoint save failed for run %s (attempt %d/%d): %s",
                    self.run_id,
                    attempt,
                    attempts,
                    exc,
                )
                if attempt < attempts and delay > 0:
                    await asyncio.sleep(delay)
                    delay *= 2

        assert last_error is not None
        logger.error(
            "Checkpoint save exhausted retries for run %s: %s",
            self.run_id,
            last_error,
        )
        raise last_error

    async def _check_fence(self) -> None:
        load = getattr(self.store, "load", None)
        if not callable(load):
            return
        try:
            latest = await load(self.run_id)
        except Exception as exc:  # noqa: BLE001 - fence check must not crash save
            logger.debug("Checkpoint fence probe failed for run %s: %s", self.run_id, exc)
            return
        if latest is None:
            return
        metadata = getattr(latest, "metadata", None)
        token, generation = inspect_remote_fence(metadata if isinstance(metadata, dict) else None)
        assert_writable_fence(self._fence, token, generation)

    def _stamp_fence(self) -> None:
        if self._current is None:
            return
        generation = self._fence.next_generation()
        self._current.metadata["fence_token"] = self._fence.token
        self._current.metadata["fence_generation"] = generation

    async def auto_save(self, interval: float = 30.0) -> None:
        """Start (or restart) the auto-save background task.

        R1-2: a single I/O failure must not kill the loop. Failures are
        logged, health is updated, and the next interval retries.
        """

        async def _auto_save() -> None:
            while True:
                try:
                    await asyncio.sleep(max(0.0, float(interval)))
                    if not self._dirty:
                        self._health.stale = self.is_stale()
                        continue
                    await self.save()
                except asyncio.CancelledError:
                    raise
                except CheckpointFencedError:
                    logger.error(
                        "Checkpoint autosave fenced out for run %s; loop continues idle",
                        self.run_id,
                    )
                except Exception:
                    logger.exception(
                        "Periodic checkpoint save failed for run %s; autosave continues",
                        self.run_id,
                    )

        existing = self._auto_save_task
        if existing is not None and not existing.done():
            return
        self._auto_save_task = asyncio.create_task(
            _auto_save(), name=f"checkpoint-autosave-{self.run_id}"
        )

    async def stop_auto_save(self) -> None:
        task = self._auto_save_task
        if task is None:
            return
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        finally:
            if self._auto_save_task is task:
                self._auto_save_task = None


# Local file implementation
class LocalCheckpointStore:
    def __init__(self, root: Path):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def _sanitize_run_id(self, run_id: str) -> str:
        if not run_id or not _SAFE_RUN_ID.fullmatch(run_id) or ".." in run_id:
            raise ValueError(f"invalid checkpoint run_id: {run_id!r}")
        resolved = (self.root / run_id).resolve()
        if not resolved.is_relative_to(self.root.resolve()):
            raise ValueError(f"checkpoint run_id escapes store root: {run_id!r}")
        return run_id

    def _run_dir(self, run_id: str) -> Path:
        return self.root / self._sanitize_run_id(run_id) / "checkpoints"

    def _version_file(self, run_id: str, version: int) -> Path:
        return self._run_dir(run_id) / f"v{version:06d}.json"

    def _latest_link(self, run_id: str) -> Path:
        return self._run_dir(run_id) / "latest.json"

    async def save(self, data: CheckpointData) -> str:
        run_dir = self._run_dir(data.run_id)
        run_dir.mkdir(parents=True, exist_ok=True)

        version = data.version
        path = self._version_file(data.run_id, version)
        tmp = path.with_suffix(path.suffix + ".tmp")
        latest = self._latest_link(data.run_id)
        latest_tmp = latest.with_name(latest.name + ".tmp")
        try:
            _atomic_write_text(tmp, data.to_json())
            os.replace(tmp, path)
            # Atomic pointer file (not a symlink): unlink+symlink raced and
            # broke on Windows / some container filesystems.
            _atomic_write_text(latest_tmp, json.dumps({"version": version}))
            os.replace(latest_tmp, latest)
            return f"v{version:06d}"
        except Exception:
            for leftover in (tmp, latest_tmp):
                try:
                    leftover.unlink(missing_ok=True)
                except OSError:
                    pass
            raise

    async def load(self, run_id: str, version: int | None = None) -> CheckpointData | None:
        if version is None:
            latest = self._latest_link(run_id)
            if not latest.exists() and not latest.is_symlink():
                return None
            # Prefer the atomic pointer file written by ``save``. Fall
            # back to a legacy symlink that pointed at ``vNNNNNN.json``.
            try:
                pointer = json.loads(latest.read_text(encoding="utf-8"))
                if isinstance(pointer, dict) and "version" in pointer:
                    version = int(pointer["version"])
            except (OSError, ValueError, TypeError, json.JSONDecodeError):
                version = None
            if version is None:
                target = latest.resolve() if latest.exists() or latest.is_symlink() else None
                if target is None or not target.exists():
                    return None
                stem = target.stem
                if stem.startswith("v") and stem[1:].isdigit():
                    version = int(stem[1:])
                else:
                    try:
                        return CheckpointData.from_json(target.read_text(encoding="utf-8"))
                    except (ValueError, TypeError):
                        return None

        path = self._version_file(run_id, version)
        if not path.exists():
            return None
        try:
            return CheckpointData.from_json(path.read_text())
        except (ValueError, TypeError):
            return None

    async def list_versions(self, run_id: str) -> list[int]:
        run_dir = self._run_dir(run_id)
        if not run_dir.exists():
            return []
        versions = []
        for f in run_dir.glob("v*.json"):
            try:
                v = int(f.stem.replace("v", ""))
                versions.append(v)
            except ValueError:
                pass
        return sorted(versions)

    async def delete(self, run_id: str, version: int) -> bool:
        path = self._version_file(run_id, version)
        if path.exists():
            path.unlink()
            return True
        return False

    async def prune(self, run_id: str, keep_last: int) -> int:
        versions = await self.list_versions(run_id)
        if len(versions) <= keep_last:
            return 0
        deleted = 0
        for v in versions[:-keep_last]:
            if await self.delete(run_id, v):
                deleted += 1
        return deleted
