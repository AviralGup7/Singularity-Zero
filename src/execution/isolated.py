"""Process isolation for active checks."""

from __future__ import annotations

import asyncio
import inspect
import logging
import multiprocessing as mp
import os
import pickle
import queue
import signal
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from src.execution.active_manifest import ActiveCheckManifest

logger = logging.getLogger(__name__)

_PICKLE_SAFETY_NOTE = (
    "SECURITY: pickle is used here ONLY for internal IPC between parent/child "
    "processes within the same trust boundary. NEVER pickle.loads() data from "
    "external or untrusted sources - this can lead to remote code execution."
)
logger.debug(_PICKLE_SAFETY_NOTE)

# Process join timeout configurable via environment variable (default: 0.5s)
PROCESS_JOIN_TIMEOUT = float(os.getenv("PROCESS_JOIN_TIMEOUT", "0.5"))


@dataclass(frozen=True, slots=True)
class IsolatedExecutionResult:
    ok: bool
    value: Any = None
    error: str = ""
    reason: str = ""
    duration_seconds: float = 0.0
    killed: bool = False
    manifest: dict[str, Any] | None = None


@dataclass(frozen=True, slots=True)
class IsolatedResponseCacheFactory:
    """Serializable marker that builds a fresh response cache inside the child."""

    timeout_seconds: int = 12


def _materialize_child_value(value: Any) -> Any:
    if isinstance(value, IsolatedResponseCacheFactory):
        from src.analysis.passive.runtime import RequestScheduler, ResponseCache

        scheduler = RequestScheduler(rate_per_second=4.0, capacity=2.0, adaptive_mode=False)
        return ResponseCache(
            timeout_seconds=value.timeout_seconds,
            max_bytes=120_000,
            max_workers=2,
            scheduler=scheduler,
            persistent_cache_path=None,
            cache_ttl_hours=1,
        )
    if isinstance(value, tuple):
        return tuple(_materialize_child_value(item) for item in value)
    if isinstance(value, list):
        return [_materialize_child_value(item) for item in value]
    if isinstance(value, dict):
        return {key: _materialize_child_value(item) for key, item in value.items()}
    return value


def replace_unpicklable_response_caches(value: Any, memo: set[int] | None = None) -> Any:
    """Swap live response-cache instances for child-local factories."""
    if memo is None:
        memo = set()
    val_id = id(value)
    if val_id in memo:
        return value
    memo.add(val_id)

    if hasattr(value, "get") and hasattr(value, "prefetch"):
        return IsolatedResponseCacheFactory()
    if isinstance(value, tuple):
        return tuple(replace_unpicklable_response_caches(item, memo) for item in value)
    if isinstance(value, list):
        return [replace_unpicklable_response_caches(item, memo) for item in value]
    if isinstance(value, dict):
        return {key: replace_unpicklable_response_caches(item, memo) for key, item in value.items()}
    return value


# Note: The following test stub functions are required for spawn-based
# child process serialization during unit test execution.
def _isolated_test_return_findings(*_args: Any, **_kwargs: Any) -> list[dict[str, str]]:
    return [{"url": "https://example.com", "severity": "info"}]


def _isolated_test_sleep_forever() -> list[dict[str, str]]:
    while True:
        time.sleep(0.05)


def _child_entry(
    output: mp.Queue,
    func: Callable[..., Any],
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    max_output_bytes: int,
) -> None:
    try:
        args = _materialize_child_value(args)
        kwargs = _materialize_child_value(kwargs)
        if inspect.iscoroutinefunction(func):
            result = asyncio.run(func(*args, **kwargs))
        else:
            result = func(*args, **kwargs)
            if inspect.isawaitable(result):
                result = asyncio.run(result)  # type: ignore[arg-type]

        payload = pickle.dumps(result)
        if len(payload) > max_output_bytes:
            output.put(
                {
                    "ok": False,
                    "reason": "output_too_large",
                    "error": f"active check output exceeded {max_output_bytes} bytes",
                }
            )
            return
        output.put({"ok": True, "value": result})
    except BaseException as exc:
        output.put(
            {
                "ok": False,
                "reason": "exception",
                "error": f"{exc.__class__.__name__}: {exc}",
            }
        )


def _terminate_process(process: Any) -> bool:
    if not process.is_alive():
        process.join(timeout=1.0)
        return False
    try:
        if sys.platform != "win32" and process.pid:
            os.kill(process.pid, signal.SIGTERM)
        else:
            process.terminate()
        process.join(timeout=PROCESS_JOIN_TIMEOUT)
        if process.is_alive():
            logger.warning(
                "Process %s (pid=%s) is still alive after SIGTERM timeout. Escalating to SIGKILL.",
                process.name,
                process.pid,
            )
            try:
                process.kill()
            except (ProcessLookupError, OSError) as exc:
                logger.warning("Operation failed in isolated.py: %s", exc, exc_info=True)  # noqa: BLE001
            process.join(timeout=PROCESS_JOIN_TIMEOUT)
        return True
    except (ProcessLookupError, OSError):
        return False


def run_callable_isolated(
    func: Callable[..., Any],
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    manifest: ActiveCheckManifest,
) -> IsolatedExecutionResult:
    """Run a callable in a child process and revoke it at the manifest budget wall."""
    budget = manifest.budget.normalized()
    started = time.monotonic()

    try:
        pickle.dumps((func, args, kwargs))
    except Exception as exc:
        return IsolatedExecutionResult(
            ok=False,
            reason="serialization_error",
            error=f"{exc.__class__.__name__}: {exc}",
            duration_seconds=round(time.monotonic() - started, 4),
            manifest=manifest.as_dict(),
        )

    import sys

    ctx: Any
    try:
        if sys.platform == "win32":
            ctx = mp.get_context("spawn")
        elif sys.platform == "darwin":
            ctx = mp.get_context("spawn")
        else:
            ctx = mp.get_context("fork")
    except ValueError:
        ctx = mp.get_context("spawn")
    output: mp.Queue = ctx.Queue(maxsize=1)
    process = ctx.Process(  # type: ignore[attr-defined]
        target=_child_entry,
        args=(output, func, args, kwargs, budget.max_output_bytes),
        daemon=True,
    )
    process.start()

    try:
        payload = output.get(timeout=budget.timeout_seconds)
    except queue.Empty:
        payload = None

    duration = round(time.monotonic() - started, 4)
    if payload is None:
        killed = _terminate_process(process)
        if killed:
            return IsolatedExecutionResult(
                ok=False,
                reason="timeout",
                error=f"active check exceeded {budget.timeout_seconds}s budget",
                duration_seconds=duration,
                killed=True,
                manifest=manifest.as_dict(),
            )
        else:
            try:
                payload = output.get(timeout=1.0)
            except queue.Empty:
                payload = None
    else:
        _terminate_process(process)

    if payload is None:
        exitcode = process.exitcode
        return IsolatedExecutionResult(
            ok=False,
            reason="crash",
            error=f"active check process exited without result (exitcode={exitcode})",
            duration_seconds=duration,
            manifest=manifest.as_dict(),
        )

    if not isinstance(payload, dict) or not payload.get("ok"):
        return IsolatedExecutionResult(
            ok=False,
            value=None,
            reason=str(payload.get("reason", "error")) if isinstance(payload, dict) else "error",
            error=str(payload.get("error", payload)) if isinstance(payload, dict) else str(payload),
            duration_seconds=duration,
            manifest=manifest.as_dict(),
        )

    return IsolatedExecutionResult(
        ok=True,
        value=payload.get("value"),
        duration_seconds=duration,
        manifest=manifest.as_dict(),
    )
