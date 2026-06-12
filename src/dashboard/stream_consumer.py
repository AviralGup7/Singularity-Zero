"""Stream consumer and log processing utilities for pipeline execution output."""

import json
import logging
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any, TextIO

from src.dashboard.job_state import append_log, apply_progress
from src.dashboard.registry import PROGRESS_PREFIX

logger = logging.getLogger(__name__)


def _last_progress_payload_from_file(path: Path, *, progress_prefix: str) -> dict[str, Any]:
    """Retrieve the last written progress JSON payload from the stdout log file."""
    try:
        lines = [
            line.strip()
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines()
            if line.strip()
        ]
    except OSError:
        return {}

    last_payload: dict[str, Any] = {}
    for line in lines:
        if not line.startswith(progress_prefix):
            continue
        try:
            parsed = json.loads(line[len(progress_prefix) :])
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            last_payload = parsed
    return last_payload


def consume_stream(
    job: dict[str, Any],
    stream: TextIO,
    sink: TextIO,
    source: str,
    lock: threading.Lock,
    persist_callback: Callable[[dict[str, Any]], None] | None = None,
) -> None:
    """Consume an execution process stream (stdout/stderr) and update job progress state."""

    def _persist_if_needed(*, force: bool = False) -> None:
        if persist_callback is None:
            return
        now = time.time()
        last_persist = float(job.get("_persist_last_epoch", 0.0) or 0.0)
        if not force and (now - last_persist) < 2.0:
            return
        job["_persist_last_epoch"] = now
        try:
            persist_callback(job)
        except Exception:  # noqa: S110
            # Persistence is best-effort and must not break pipeline execution.
            pass

    try:
        for raw_line in iter(stream.readline, ""):
            try:
                sink.write(raw_line)
                sink.flush()
                line = raw_line.rstrip()
                if not line:
                    continue
                if source == "stdout" and line.startswith(PROGRESS_PREFIX):
                    try:
                        payload = json.loads(line[len(PROGRESS_PREFIX) :])
                    except json.JSONDecodeError:
                        payload = None
                    if isinstance(payload, dict):
                        with lock:
                            apply_progress(job, payload)
                            _persist_if_needed()
                        continue

                with lock:
                    if source == "stderr" and line.lower().startswith("warning"):
                        warning_text = line.strip()
                        job["warnings"].append(warning_text)
                        job["warnings"] = job["warnings"][-10:]
                prefix = "stderr: " if source == "stderr" else ""
                append_log(job, f"{prefix}{line}")
            except Exception as exc:
                with lock:
                    append_log(job, f"Stream error ({source}): {exc}")
                    # Mark status as failed and set error details to prevent hanging
                    job["status"] = "failed"
                    job["error"] = f"Stream consumer crashed: {exc}"
                    job["failed_stage"] = job.get("stage") or "running"
                    job["failure_reason_code"] = "stream_consumer_crash"
                    job["failure_reason"] = f"Stream consumer crashed ({source}): {exc}"
                    process = job.get("process")
                    if process:
                        try:
                            process.kill()
                        except (OSError, ProcessLookupError) as kill_exc:
                            logger.debug("Stream consumer process kill failed: %s", kill_exc)
                    _persist_if_needed(force=True)
                break
    except Exception as exc:
        with lock:
            append_log(job, f"Stream consumer outer error ({source}): {exc}")
            job["status"] = "failed"
            job["error"] = f"Stream consumer failed: {exc}"
            job["failed_stage"] = job.get("stage") or "running"
            job["failure_reason_code"] = "stream_consumer_crash"
            job["failure_reason"] = f"Stream consumer failed ({source}): {exc}"
            _persist_if_needed(force=True)
    finally:
        stream.close()
        try:
            sink.close()
        except Exception:  # noqa: S110
            pass
