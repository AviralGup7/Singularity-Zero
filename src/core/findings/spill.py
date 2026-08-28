"""Append-only findings spill: survives WAL/outbox/DB corruption mid-run.

Every candidate is written as one JSONL line *before* settlement/dedup
attempts. Recovery merges by ``spill_id`` + fingerprint without
double-settling.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

SPILL_ENABLED_ENV = "FINDINGS_SPILL_ENABLED"
SPILL_FSYNC_EVERY_ENV = "FINDINGS_SPILL_FSYNC_EVERY"


def spill_enabled() -> bool:
    raw = os.environ.get(SPILL_ENABLED_ENV, "true").strip().lower()
    return raw not in {"0", "false", "no", "off"}


def _fsync_every() -> int:
    try:
        return max(1, int(os.environ.get(SPILL_FSYNC_EVERY_ENV, "50")))
    except ValueError:
        return 50


def _fingerprint(payload: dict[str, Any]) -> str:
    for key in ("event_id", "spill_id", "id"):
        value = payload.get(key)
        if value:
            return str(value)
    basis = "|".join(
        str(payload.get(k) or "")
        for k in ("tool", "url", "category", "title", "parameter", "method")
    )
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()[:32]


def _payload_sha256(payload: dict[str, Any]) -> str:
    blob = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


@dataclass
class FindingSpill:
    """Per-run JSONL spill file."""

    run_id: str
    path: Path
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    _written: int = 0
    _since_fsync: int = 0

    @classmethod
    def for_run(cls, run_id: str, output_dir: Path | str | None = None) -> FindingSpill:
        root = Path(output_dir) if output_dir else Path("output")
        directory = root / str(run_id or "unknown")
        directory.mkdir(parents=True, exist_ok=True)
        return cls(run_id=str(run_id or "unknown"), path=directory / "findings.spill.jsonl")

    def append(
        self,
        finding: dict[str, Any],
        *,
        stage: str = "",
        force: bool = False,
    ) -> dict[str, Any] | None:
        if not force and not spill_enabled():
            return None
        payload = dict(finding)
        spill_id = str(payload.get("spill_id") or "")
        if not spill_id:
            spill_id = hashlib.sha256(
                f"{self.run_id}:{stage}:{_fingerprint(payload)}:{time.time_ns()}".encode()
            ).hexdigest()[:24]
            payload["spill_id"] = spill_id
        record = {
            "spill_id": spill_id,
            "run_id": self.run_id,
            "stage": stage,
            "fingerprint": _fingerprint(payload),
            "ts_mono": time.monotonic(),
            "sha256": _payload_sha256(payload),
            "finding": payload,
        }
        line = json.dumps(record, sort_keys=True, default=str) + "\n"
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.path, "a", encoding="utf-8") as handle:
                handle.write(line)
                self._written += 1
                self._since_fsync += 1
                if self._since_fsync >= _fsync_every():
                    handle.flush()
                    try:
                        os.fsync(handle.fileno())
                    except OSError:
                        pass
                    self._since_fsync = 0
        return record

    def flush(self) -> None:
        with self._lock:
            if not self.path.exists():
                return
            with open(self.path, "a", encoding="utf-8") as handle:
                handle.flush()
                try:
                    os.fsync(handle.fileno())
                except OSError:
                    pass
            self._since_fsync = 0

    def read_all(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        rows: list[dict[str, Any]] = []
        try:
            for line in self.path.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                try:
                    item = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(item, dict):
                    rows.append(item)
        except OSError as exc:
            logger.warning("spill read failed %s: %s", self.path, exc)
        return rows

    def findings(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for row in self.read_all():
            finding = row.get("finding")
            if isinstance(finding, dict):
                out.append(finding)
        return out


_default_lock = threading.Lock()
_spills: dict[str, FindingSpill] = {}


def spill_finding(
    finding: dict[str, Any],
    *,
    run_id: str,
    stage: str = "",
    output_dir: Path | str | None = None,
) -> dict[str, Any] | None:
    if not spill_enabled() or not isinstance(finding, dict):
        return None
    key = f"{output_dir}:{run_id}"
    with _default_lock:
        spill = _spills.get(key)
        if spill is None:
            spill = FindingSpill.for_run(run_id, output_dir)
            _spills[key] = spill
    return spill.append(finding, stage=stage)


class SpillMerger:
    """Idempotent reconcile: settle only spill rows not yet in outbox."""

    def reconcile(
        self,
        run_id: str,
        *,
        output_dir: Path | str | None = None,
        existing_ids: set[str] | None = None,
    ) -> list[dict[str, Any]]:
        spill = FindingSpill.for_run(run_id, output_dir)
        seen = set(existing_ids or ())
        pending: list[dict[str, Any]] = []
        for row in spill.read_all():
            fingerprint = str(row.get("fingerprint") or "")
            spill_id = str(row.get("spill_id") or "")
            token = f"{spill_id}:{fingerprint}"
            if token in seen or fingerprint in seen or spill_id in seen:
                continue
            seen.add(token)
            finding = row.get("finding")
            if isinstance(finding, dict):
                pending.append(finding)
        return pending


FINDINGS_SPILL_ENABLED = SPILL_ENABLED_ENV

__all__ = [
    "FINDINGS_SPILL_ENABLED",
    "FindingSpill",
    "SPILL_ENABLED_ENV",
    "SpillMerger",
    "spill_enabled",
    "spill_finding",
]
