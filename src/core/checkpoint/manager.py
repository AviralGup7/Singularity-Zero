from __future__ import annotations

import abc
import asyncio
import hashlib
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TypeVar

T = TypeVar("T")


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
        return cls(**parsed)

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

    async def load(self) -> CheckpointData | None:
        """Load latest checkpoint."""
        data = await self.store.load(self.run_id)
        if data:
            self._current = data
            self._version = data.version
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
        """Save checkpoint if dirty or forced."""
        if not self._dirty and not force:
            return None
        if not self._current:
            return None

        self._version += 1
        self._current.version = self._version
        self._current.timestamp = time.time()
        version_id = await self.store.save(self._current)
        self._dirty = False
        return version_id

    async def auto_save(self, interval: float = 30.0):
        """Start auto-save background task."""

        async def _auto_save():
            while True:
                await asyncio.sleep(interval)
                if self._dirty:
                    await self.save()

        self._auto_save_task = asyncio.create_task(_auto_save())

    async def stop_auto_save(self):
        if self._auto_save_task:
            self._auto_save_task.cancel()
            try:
                await self._auto_save_task
            except asyncio.CancelledError:
                pass


# Local file implementation
class LocalCheckpointStore:
    def __init__(self, root: Path):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def _run_dir(self, run_id: str) -> Path:
        return self.root / run_id / "checkpoints"

    def _version_file(self, run_id: str, version: int) -> Path:
        return self._run_dir(run_id) / f"v{version:06d}.json"

    def _latest_link(self, run_id: str) -> Path:
        return self._run_dir(run_id) / "latest.json"

    async def save(self, data: CheckpointData) -> str:
        run_dir = self._run_dir(data.run_id)
        run_dir.mkdir(parents=True, exist_ok=True)

        version = data.version
        path = self._version_file(data.run_id, version)
        path.write_text(data.to_json())

        # Update latest symlink
        latest = self._latest_link(data.run_id)
        if latest.exists() or latest.is_symlink():
            latest.unlink()
        latest.symlink_to(path.name)

        return f"v{version:06d}"

    async def load(self, run_id: str, version: int | None = None) -> CheckpointData | None:
        if version is None:
            latest = self._latest_link(run_id)
            if not latest.exists():
                return None
            version = int(latest.read_text().strip().split(".")[0].replace("v", ""))

        path = self._version_file(run_id, version)
        if not path.exists():
            return None
        return CheckpointData.from_json(path.read_text())

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
