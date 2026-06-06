from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

from .interfaces import ArtifactStore, CheckpointStore, FindingStore, VersionId


def _parse_version_id(version_id: VersionId) -> int:
    """Parse an opaque ``VersionId`` produced by :class:`LocalCheckpointStore`.

    Local backends use ``"v{n}"`` (e.g. ``"v3"``). Any other shape is a
    caller error and is reported as ``ValueError`` rather than silently
    treated as a relative path, so a misbehaving caller cannot escape
    the run directory by smuggling a ``"../"`` segment.
    """
    if not isinstance(version_id, str) or not version_id.startswith("v"):
        raise ValueError(f"Invalid checkpoint version id: {version_id!r}")
    suffix = version_id[1:]
    if not suffix.isdigit():
        raise ValueError(f"Invalid checkpoint version id: {version_id!r}")
    return int(suffix)


def _stage_safe_name(stage_name: str) -> str:
    safe = str(stage_name or "").strip() or "unknown"
    if any(c in safe for c in ("/", "\\", "..")):
        raise ValueError(f"Invalid stage name: {stage_name!r}")
    return safe


class LocalArtifactStore(ArtifactStore):
    def __init__(self, root: Path) -> None:
        self._root = Path(root)
        self._root.mkdir(parents=True, exist_ok=True)

    def put(self, key: str, payload: bytes) -> str:
        path = self._root / key
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        return str(path)

    def get(self, key: str) -> bytes:
        return (self._root / key).read_bytes()

    def exists(self, key: str) -> bool:
        return (self._root / key).exists()

    def delete(self, key: str) -> None:
        path = self._root / key
        try:
            path.unlink()
        except FileNotFoundError:
            logger.debug("File to delete not found: %s", path)

    def list(self, prefix: str = "") -> list[str]:
        prefix_path = self._root / prefix
        if not prefix_path.exists():
            return []

        results = []
        for p in prefix_path.rglob("*"):
            if p.is_file():
                results.append(p.relative_to(self._root).as_posix())
        return sorted(results)


class LocalCheckpointStore(CheckpointStore):
    """Filesystem-backed CheckpointStore.

    On-disk layout::

        <root>/<run_id>/checkpoint_v<n>.json
        <root>/<run_id>/context_<stage>.json
        <root>/<run_id>/delta_<stage>_<seq:06>.json
    """

    def __init__(self, root: Path) -> None:
        self._root = Path(root)
        self._root.mkdir(parents=True, exist_ok=True)

    def _run_dir(self, run_id: str) -> Path:
        path = self._root / run_id
        path.mkdir(parents=True, exist_ok=True)
        return path

    def list_run_ids(self) -> list[str]:
        if not self._root.is_dir():
            return []
        return sorted(
            entry.name
            for entry in self._root.iterdir()
            if entry.is_dir()
        )

    def _checkpoint_path(self, run_id: str, version: int) -> Path:
        return self._run_dir(run_id) / f"checkpoint_v{version}.json"

    @staticmethod
    def _version_id_from_filename(path: Path) -> int:
        """Extract the integer version from a ``checkpoint_v<n>`` filename."""
        stem = path.stem
        if not stem.startswith("checkpoint_v"):
            raise ValueError(f"Not a checkpoint file: {path}")
        return int(stem[len("checkpoint_v"):])

    def _context_snapshot_path(self, run_id: str, stage_name: str) -> Path:
        return self._run_dir(run_id) / f"context_{_stage_safe_name(stage_name)}.json"

    def _stage_delta_path(
        self, run_id: str, stage_name: str, sequence: int
    ) -> Path:
        return (
            self._run_dir(run_id)
            / f"delta_{_stage_safe_name(stage_name)}_{sequence:06d}.json"
        )

    def write(self, run_id: str, version: int, payload: dict[str, Any]) -> VersionId:
        target = self._checkpoint_path(run_id, version)
        temp = target.with_suffix(".tmp")
        temp.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        temp.replace(target)
        return f"v{version}"

    def read_latest(self, run_id: str | None = None) -> dict[str, Any] | None:
        if run_id:
            candidates = sorted(
                (self._root / run_id).glob("checkpoint_v*.json"),
                key=self._version_id_from_filename,
            )
            if not candidates:
                return None
            return dict(json.loads(candidates[-1].read_text(encoding="utf-8")))

        latest: tuple[int, float, dict[str, Any]] | None = None
        for folder in self._root.iterdir():
            if not folder.is_dir():
                continue
            candidates = sorted(
                folder.glob("checkpoint_v*.json"),
                key=self._version_id_from_filename,
            )
            if not candidates:
                continue
            path = candidates[-1]
            try:
                payload = dict(json.loads(path.read_text(encoding="utf-8")))
            except (OSError, json.JSONDecodeError):
                continue
            version = self._version_id_from_filename(path)
            mtime = path.stat().st_mtime
            if latest is None or (version, mtime) > (latest[0], latest[1]):
                latest = (version, mtime, payload)
        return latest[2] if latest else None

    def read_version_by_id(
        self, run_id: str, version_id: VersionId
    ) -> dict[str, Any] | None:
        version = _parse_version_id(version_id)
        path = self._checkpoint_path(run_id, version)
        if not path.exists():
            return None
        try:
            return dict(json.loads(path.read_text(encoding="utf-8")))
        except (OSError, json.JSONDecodeError):
            return None

    def list_version_ids(self, run_id: str) -> list[VersionId]:
        run_dir = self._root / run_id
        if not run_dir.is_dir():
            return []
        ids: list[VersionId] = []
        for path in run_dir.glob("checkpoint_v*.json"):
            try:
                version = self._version_id_from_filename(path)
            except ValueError:
                continue
            ids.append(f"v{version}")
        ids.sort(key=lambda v: _parse_version_id(v))
        return ids

    def delete_version(self, run_id: str, version_id: VersionId) -> None:
        version = _parse_version_id(version_id)
        try:
            self._checkpoint_path(run_id, version).unlink()
        except FileNotFoundError:
            logger.debug("File to delete not found: %s", version_id)

    def write_context_snapshot(
        self, run_id: str, stage_name: str, payload: dict[str, Any]
    ) -> VersionId:
        target = self._context_snapshot_path(run_id, stage_name)
        temp = target.with_suffix(".tmp")
        temp.write_text(json.dumps(payload, default=str), encoding="utf-8")
        temp.replace(target)
        return target.name

    def read_context_snapshot(
        self, run_id: str, stage_name: str
    ) -> dict[str, Any] | None:
        path = self._context_snapshot_path(run_id, stage_name)
        if not path.exists():
            return None
        try:
            return dict(json.loads(path.read_text(encoding="utf-8")))
        except (OSError, json.JSONDecodeError):
            return None

    def write_stage_delta(
        self,
        run_id: str,
        stage_name: str,
        sequence: int,
        payload: dict[str, Any],
    ) -> VersionId:
        target = self._stage_delta_path(run_id, stage_name, sequence)
        temp = target.with_suffix(".tmp")
        temp.write_text(json.dumps(payload, default=str), encoding="utf-8")
        temp.replace(target)
        return target.name

    def list_stage_deltas(
        self, run_id: str, stage_name: str
    ) -> list[dict[str, Any]]:
        safe = _stage_safe_name(stage_name)
        run_dir = self._root / run_id
        if not run_dir.is_dir():
            return []
        results: list[dict[str, Any]] = []
        for path in sorted(run_dir.glob(f"delta_{safe}_*.json")):
            try:
                payload = dict(json.loads(path.read_text(encoding="utf-8")))
            except (OSError, json.JSONDecodeError) as exc:
                logger.warning("Failed to read stage delta %s: %s", path, exc)
                continue
            if isinstance(payload, dict):
                results.append(payload)
        results.sort(key=lambda item: int(item.get("sequence", 0) or 0))
        return results


class LocalFindingStore(FindingStore):
    def __init__(self, root: Path) -> None:
        self._root = Path(root)
        self._root.mkdir(parents=True, exist_ok=True)

    def save_many(self, run_id: str, findings: list[dict[str, Any]]) -> None:
        path = self._root / f"{run_id}.findings.json"
        path.write_text(json.dumps(findings, indent=2), encoding="utf-8")

    def load_many(self, run_id: str) -> list[dict[str, Any]]:
        path = self._root / f"{run_id}.findings.json"
        if not path.exists():
            return []
        return list(json.loads(path.read_text(encoding="utf-8")) or [])
