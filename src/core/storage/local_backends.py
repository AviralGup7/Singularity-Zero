from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .interfaces import ArtifactStore, CheckpointStore, FindingStore


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
            pass

    def list(self, prefix: str = "") -> list[str]:
        prefix_path = self._root / prefix
        if not prefix_path.exists():
            return []

        results = []
        for p in prefix_path.rglob("*"):
            if p.is_file():
                results.append(str(p.relative_to(self._root)))
        return sorted(results)


class LocalCheckpointStore(CheckpointStore):
    def __init__(self, root: Path) -> None:
        self._root = Path(root)
        self._root.mkdir(parents=True, exist_ok=True)

    def _run_dir(self, run_id: str) -> Path:
        path = self._root / run_id
        path.mkdir(parents=True, exist_ok=True)
        return path

    def write(self, run_id: str, version: int, payload: dict[str, Any]) -> Path:
        run_dir = self._run_dir(run_id)
        target = run_dir / f"checkpoint_v{version}.json"
        temp = target.with_suffix(".tmp")
        temp.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        temp.replace(target)
        return target

    def read_latest(self, run_id: str | None = None) -> dict[str, Any] | None:
        if run_id:
            candidates = sorted((self._root / run_id).glob("checkpoint_v*.json"))
            if not candidates:
                return None
            return dict(json.loads(candidates[-1].read_text(encoding="utf-8")))

        for folder in sorted(self._root.iterdir(), reverse=True):
            if not folder.is_dir():
                continue
            candidates = sorted(folder.glob("checkpoint_v*.json"))
            if candidates:
                return dict(json.loads(candidates[-1].read_text(encoding="utf-8")))
        return None

    def read_version(self, path: str | Path) -> dict[str, Any] | None:
        p = Path(path)
        if not p.exists():
            return None
        try:
            return dict(json.loads(p.read_text(encoding="utf-8")))
        except OSError, json.JSONDecodeError:
            return None

    def list_versions(self, run_id: str) -> list[str | Path]:
        return list(sorted((self._root / run_id).glob("checkpoint_v*.json")))  # type: ignore

    def delete(self, path: str | Path) -> None:
        try:
            Path(path).unlink()
        except FileNotFoundError:
            pass


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
