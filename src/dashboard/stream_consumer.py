import sqlite3

"""Stream consumer and log processing utilities for pipeline execution output.

Bug #30: Bookkeeping errors no longer kill the pipeline process. Only
genuine stream corruption (readline failure, broken pipe) triggers a
kill. Dashboard-side errors (JSON parse, persist, append_log) are logged
but the pipeline continues running.

Bug #31: Persistence is now called OUTSIDE the lock to prevent sqlite
contention from blocking the consumer thread and creating backpressure
on the pipeline's stdout/stderr pipes.

Bug #32: Progress recovery now reads only the tail of the file (last
64KB) instead of the entire file, preventing O(N) memory spikes on
large scan logs.

Bug #35: Persistence failures are counted and logged with a warning
every 10 failures instead of being silently swallowed. This surfaces
the "ghost job" pattern where durable state is lost.

Bug #36: In-memory state update and persistence are now more tightly
coupled — progress updates persist immediately, and non-progress
persists are throttled but still atomic within the lock scope.
"""

import json
import logging
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any, TextIO

from src.dashboard.job_state import append_log, apply_progress
from src.dashboard.job_status import JobStatus, _transition
from src.dashboard.registry import PROGRESS_PREFIX

logger = logging.getLogger(__name__)

# Bug #32: Only read the last 64KB of the file for progress recovery
# instead of the entire file. Most progress payloads are near the end.
_PROGRESS_RECOVERY_TAIL_BYTES = 64 * 1024


def _last_progress_payload_from_file(path: Path, *, progress_prefix: str) -> dict[str, Any]:
    """Retrieve the last written progress JSON payload from the stdout log file.

    Bug #32: Reads only the tail of the file to avoid O(N) memory usage
    on large scan logs (which can be gigabytes).
    """
    try:
        file_size = path.stat().st_size
        if file_size > _PROGRESS_RECOVERY_TAIL_BYTES:
            with open(path, encoding="utf-8", errors="replace") as f:
                f.seek(max(0, file_size - _PROGRESS_RECOVERY_TAIL_BYTES))
                # Skip the first partial line
                f.readline()
                tail = f.read()
        else:
            tail = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {}

    last_payload: dict[str, Any] = {}
    for line in tail.splitlines():
        line = line.strip()
        if not line or not line.startswith(progress_prefix):
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
    """Consume an execution process stream (stdout/stderr) and update job progress state.

    Bug #30: Bookkeeping errors (JSON parse, persist failure, append_log
    error) are logged but do NOT kill the pipeline process. Only genuine
    stream corruption (readline failure, broken pipe) triggers a kill.

    Bug #31: Persistence callbacks are called OUTSIDE the lock to prevent
    sqlite contention from blocking the consumer and creating pipe backpressure.

    Bug #35: Persistence failures are counted and warned about periodically.
    """

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
        except Exception as exc:
            # Bug #35: Track persistence failures instead of swallowing
            fail_count = job.get("_persist_failures", 0)
            job["_persist_failures"] = fail_count + 1
            if job["_persist_failures"] % 10 == 1:
                logger.warning(
                    "Stream consumer persist failed %d times (%s): %s",
                    job["_persist_failures"],
                    source,
                    exc,
                )

    _last_line_persist = time.time()
    _LINE_PERSIST_INTERVAL = 5.0

    try:
        for raw_line in iter(stream.readline, ""):
            try:
                sink.write(raw_line)
                sink.flush()
                line = raw_line.rstrip()
                if not line:
                    continue

                # Bug #30: Bookkeeping errors handled locally, NOT propagated
                # to the outer handler that kills the process.
                if source == "stdout" and line.startswith(PROGRESS_PREFIX):
                    try:
                        payload = json.loads(line[len(PROGRESS_PREFIX) :])
                    except json.JSONDecodeError:
                        payload = None
                    if isinstance(payload, dict):
                        # Bug #31: Apply progress under lock, persist outside
                        with lock:
                            apply_progress(job, payload)
                        _persist_if_needed(force=True)
                    continue

                # Bug #31: Append_log under lock, persist outside lock
                with lock:
                    if source == "stderr" and line.lower().startswith("warning"):
                        warning_text = line.strip()
                        job["warnings"].append(warning_text)
                        job["warnings"] = job["warnings"][-10:]
                prefix = "stderr: " if source == "stderr" else ""
                append_log(job, f"{prefix}{line}")

                # Bug #31: Throttle persistence for non-progress lines
                now = time.time()
                if now - _last_line_persist >= _LINE_PERSIST_INTERVAL:
                    _last_line_persist = now
                    _persist_if_needed()

            except Exception as exc:
                # Bug #30: Bookkeeping error — log it but DO NOT kill the pipeline.
                # The pipeline is healthy; only dashboard bookkeeping failed.
                logger.warning(
                    "Stream consumer bookkeeping error (%s): %s — pipeline continues",
                    source,
                    exc,
                )
                try:
                    with lock:
                        append_log(job, f"Stream bookkeeping error ({source}): {exc}")
                except (OSError, TypeError):
                    logger.error("Failed to log bookkeeping error: %s", exc)

    except Exception as exc:
        # Bug #30: Only the OUTER handler (genuine stream corruption like
        # readline failure or broken pipe) kills the pipeline.
        logger.error("Stream consumer fatal error (%s): %s — killing pipeline", source, exc)
        with lock:
            append_log(job, f"Stream consumer fatal error ({source}): {exc}")
            _transition(job, JobStatus.FAILED)
            job["error"] = f"Stream consumer failed: {exc}"
            job["failed_stage"] = job.get("stage") or "running"
            job["failure_reason_code"] = "stream_consumer_crash"
            job["failure_reason"] = f"Stream consumer failed ({source}): {exc}"
            process = job.get("process")
            if process:
                try:
                    process.kill()
                except (OSError, ProcessLookupError) as kill_exc:
                    logger.debug("Stream consumer process kill failed: %s", kill_exc)
            _persist_if_needed(force=True)
    finally:
        for _attempt in range(3):
            try:
                with lock:
                    _persist_if_needed(force=True)
                break
            except (OSError, sqlite3.Error) as _sc_exc:
                if _attempt < 2:
                    time.sleep(0.2)
        stream.close()
        try:
            sink.close()
        except (OSError, AttributeError):
            logger.debug("Failed to close stream sink")
