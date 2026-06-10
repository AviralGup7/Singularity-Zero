"""Stage-level trace store for causal replay and forensics debugging."""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import json
import re
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from src.core.logging.trace_logging import get_pipeline_logger

logger = get_pipeline_logger(__name__)

_SECRET_PATTERN = re.compile(
    r"(?i)(api[_-]?key|token|password|secret|auth|authorization|bearer)\s*[:=]\s*\S+",
)


def _redact(value: str) -> str:
    return _SECRET_PATTERN.sub(lambda m: f"{m.group(1)}: ***", value)


def _truncate(value: str | None, limit: int = 4096) -> str | None:
    if value is None:
        return None
    if len(value) > limit:
        return value[:limit] + "...[truncated]"
    return value


@dataclass
class StageTrace:
    trace_id: str
    run_id: str
    stage_name: str
    started_at: datetime
    finished_at: datetime | None
    duration_ms: float | None
    stage_input_hash: str
    tool_invocation: dict[str, Any]
    tool_stdout: str | None
    tool_stderr: str | None
    exit_code: int | None
    state_delta_keys: list[str]
    state_pre_count: int
    state_post_count: int
    findings_produced: list[str]
    finding_event_ids: list[str]
    error: str | None
    retry_count: int


class TraceStore:
    def __init__(self, trace_dir: str = ".ai/traces") -> None:
        self._dir = Path(trace_dir)
        self._dir.mkdir(parents=True, exist_ok=True)
        self._lock = asyncio.Lock()

    def _run_file(self, run_id: str) -> Path:
        safe = re.sub(r"[^A-Za-z0-9_-]", "_", run_id)
        return self._dir / f"{safe}.jsonl"

    def record_trace(self, trace: StageTrace) -> str:
        path = self._run_file(trace.run_id)
        payload = asdict(trace)
        payload["started_at"] = trace.started_at.isoformat()
        if trace.finished_at is not None:
            payload["finished_at"] = trace.finished_at.isoformat()
        line = json.dumps(payload, default=str, sort_keys=True)
        try:
            with open(path, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        except OSError as exc:
            logger.warning(
                "TraceStore write failed for run=%s stage=%s: %s",
                trace.run_id,
                trace.stage_name,
                exc,
            )
        return trace.trace_id

    async def record_trace_async(self, trace: StageTrace) -> str:
        async with self._lock:
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(None, self.record_trace, trace)
        return trace.trace_id

    def get_traces_for_run(self, run_id: str) -> list[StageTrace]:
        path = self._run_file(run_id)
        if not path.exists():
            return []
        traces: list[StageTrace] = []
        try:
            with open(path, encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        payload = json.loads(line)
                        payload["started_at"] = datetime.fromisoformat(payload["started_at"])
                        if payload.get("finished_at"):
                            payload["finished_at"] = datetime.fromisoformat(payload["finished_at"])
                        traces.append(StageTrace(**payload))
                    except (json.JSONDecodeError, TypeError, KeyError) as exc:
                        logger.debug("Skipping malformed trace line: %s", exc)
        except OSError as exc:
            logger.warning("TraceStore read failed for run=%s: %s", run_id, exc)
        return traces

    def get_trace_for_stage(self, run_id: str, stage_name: str) -> StageTrace | None:
        for trace in self.get_traces_for_run(run_id):
            if trace.stage_name == stage_name:
                return trace
        return None

    def get_finding_causal_chain(self, finding_id: str, run_id: str) -> list[StageTrace]:
        return [
            t for t in self.get_traces_for_run(run_id) if finding_id in (t.findings_produced or [])
        ]


def build_tool_invocation(stage_input: Any, method: Any) -> dict[str, Any]:
    invocation: dict[str, Any] = {}
    try:
        cfg = getattr(stage_input, "config", None) or getattr(stage_input, "runtime", None) or {}
        invocation["runtime_mode"] = str(getattr(cfg, "mode", "") or "")
        invocation["runtime_filters"] = dict(getattr(cfg, "filters", {}) or {})
    except (AttributeError, TypeError) as exc:
        logger.debug("Failed to extract runtime config: %s", exc)
        invocation["runtime_mode"] = ""
        invocation["runtime_filters"] = {}

    try:
        src = inspect.getsource(method)
        invocation["method_source_hash"] = hashlib.sha256(src.encode()).hexdigest()[:16]
    except (TypeError, OSError) as exc:
        logger.debug("Failed to get method source: %s", exc)
        invocation["method_source_hash"] = ""

    return invocation


def redact_tool_invocation(invocation: dict[str, Any]) -> dict[str, Any]:
    redacted: dict[str, Any] = {}
    for key, value in invocation.items():
        if isinstance(value, str):
            redacted[key] = _redact(value)
        elif isinstance(value, dict):
            redacted[key] = redact_tool_invocation(value)
        else:
            redacted[key] = value
    return redacted


def compute_stage_input_hash(stage_input: Any) -> str:
    try:
        raw = json.dumps(stage_input.to_dict(), sort_keys=True, default=str)
        return hashlib.sha256(raw.encode()).hexdigest()
    except Exception as exc:
        logger.debug("Failed to hash stage_input: %s", exc)
        return hashlib.sha256(str(stage_input).encode()).hexdigest()


def extract_findings_from_output(stage_output: Any) -> list[str]:
    findings: list[str] = []
    try:
        delta = getattr(stage_output, "state_delta", {}) or {}
        raw = delta.get("reportable_findings", []) or []
        for item in raw:
            if isinstance(item, dict):
                fid = item.get("finding_id") or item.get("id") or item.get("title", "unknown")
                findings.append(str(fid))
    except (AttributeError, TypeError, KeyError) as exc:
        logger.debug("Failed to extract findings from output: %s", exc)
    return findings


def make_trace_id() -> str:
    return str(__import__("uuid").uuid4())


_trace_store: TraceStore | None = None


def get_trace_store(trace_dir: str = ".ai/traces") -> TraceStore:
    global _trace_store
    if _trace_store is None:
        _trace_store = TraceStore(trace_dir=trace_dir)
    return _trace_store
