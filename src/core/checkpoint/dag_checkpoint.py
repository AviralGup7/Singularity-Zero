"""DAG execution checkpoint independent of PartitionFSM.

Persists stage_status / attempts so a SIGKILL mid-scan can resume or
auto-finalize a partial report instead of losing all progress.
"""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

DAG_CHECKPOINT_ENABLED_ENV = "DAG_CHECKPOINT_ENABLED"
AUTO_FINALIZE_ENV = "AUTO_FINALIZE_CRASHED_ON_STARTUP"
HEARTBEAT_ENV = "DAG_CHECKPOINT_HEARTBEAT_S"

RUNNING_STATUSES = frozenset({"STARTING", "RUNNING"})


def dag_checkpoint_enabled() -> bool:
    raw = os.environ.get(DAG_CHECKPOINT_ENABLED_ENV, "true").strip().lower()
    return raw not in {"0", "false", "no", "off"}


def auto_finalize_crashed() -> bool:
    raw = os.environ.get(AUTO_FINALIZE_ENV, "false").strip().lower()
    return raw in {"1", "true", "yes", "on"}


def heartbeat_seconds() -> float:
    try:
        return max(1.0, float(os.environ.get(HEARTBEAT_ENV, "15")))
    except ValueError:
        return 15.0


@dataclass
class DagCheckpoint:
    run_id: str
    status: str = "RUNNING"
    stage_status: dict[str, str] = field(default_factory=dict)
    completed: list[str] = field(default_factory=list)
    failed: list[str] = field(default_factory=list)
    ready_queue: list[str] = field(default_factory=list)
    start_ts: float = field(default_factory=time.time)
    last_heartbeat_ts: float = field(default_factory=time.time)
    current_stage: str = ""
    findings_count_so_far: int = 0
    outputs_paths: dict[str, str] = field(default_factory=dict)
    clean_exit: bool = False
    graph_gen_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "status": self.status,
            "stage_status": dict(self.stage_status),
            "completed": list(self.completed),
            "failed": list(self.failed),
            "ready_queue": list(self.ready_queue),
            "start_ts": self.start_ts,
            "last_heartbeat_ts": self.last_heartbeat_ts,
            "current_stage": self.current_stage,
            "findings_count_so_far": self.findings_count_so_far,
            "outputs_paths": dict(self.outputs_paths),
            "clean_exit": self.clean_exit,
            "graph_gen_id": self.graph_gen_id,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> DagCheckpoint:
        return cls(
            run_id=str(raw.get("run_id") or ""),
            status=str(raw.get("status") or "RUNNING"),
            stage_status={str(k): str(v) for k, v in dict(raw.get("stage_status") or {}).items()},
            completed=[str(x) for x in (raw.get("completed") or [])],
            failed=[str(x) for x in (raw.get("failed") or [])],
            ready_queue=[str(x) for x in (raw.get("ready_queue") or [])],
            start_ts=float(raw.get("start_ts") or 0.0),
            last_heartbeat_ts=float(raw.get("last_heartbeat_ts") or 0.0),
            current_stage=str(raw.get("current_stage") or ""),
            findings_count_so_far=int(raw.get("findings_count_so_far") or 0),
            outputs_paths={str(k): str(v) for k, v in dict(raw.get("outputs_paths") or {}).items()},
            clean_exit=bool(raw.get("clean_exit")),
            graph_gen_id=str(raw.get("graph_gen_id") or ""),
        )

    def is_crashed_in_progress(self) -> bool:
        return (not self.clean_exit) and self.status in RUNNING_STATUSES

    def is_worker_dead(
        self, *, now: float | None = None, dead_after_s: float | None = None
    ) -> bool:
        ttl = dead_after_s
        if ttl is None:
            try:
                ttl = float(os.environ.get("RUN_DEAD_AFTER_S", "120"))
            except ValueError:
                ttl = 120.0
        ts = time.time() if now is None else float(now)
        if not self.last_heartbeat_ts:
            return self.is_crashed_in_progress()
        return (not self.clean_exit) and (ts - self.last_heartbeat_ts) >= float(ttl)


class DagCheckpointStore:
    def __init__(self, path: Path | str) -> None:
        self._path = Path(path)

    def save(self, checkpoint: DagCheckpoint) -> None:
        if not dag_checkpoint_enabled():
            return
        checkpoint.last_heartbeat_ts = time.time()
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._path.with_suffix(self._path.suffix + ".tmp")
        payload = json.dumps(checkpoint.to_dict(), sort_keys=True)
        tmp.write_text(payload, encoding="utf-8")
        os.replace(tmp, self._path)

    def load(self) -> DagCheckpoint | None:
        if not self._path.exists():
            return None
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("dag checkpoint unreadable %s: %s", self._path, exc)
            return None
        if not isinstance(raw, dict):
            return None
        return DagCheckpoint.from_dict(raw)

    def mark_clean_exit(self, checkpoint: DagCheckpoint, status: str = "COMPLETED") -> None:
        checkpoint.status = status
        checkpoint.clean_exit = True
        self.save(checkpoint)


def detect_crashed_runs(root: Path | str) -> list[DagCheckpoint]:
    base = Path(root)
    if not base.exists():
        return []
    crashed: list[DagCheckpoint] = []
    for path in base.rglob("dag_checkpoint.json"):
        store = DagCheckpointStore(path)
        snap = store.load()
        if snap is not None and snap.is_crashed_in_progress():
            crashed.append(snap)
    return crashed


__all__ = [
    "AUTO_FINALIZE_ENV",
    "DAG_CHECKPOINT_ENABLED_ENV",
    "DagCheckpoint",
    "DagCheckpointStore",
    "auto_finalize_crashed",
    "dag_checkpoint_enabled",
    "detect_crashed_runs",
    "heartbeat_seconds",
]
