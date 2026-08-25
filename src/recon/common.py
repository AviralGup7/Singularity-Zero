"""Common recon utilities for parallel command execution and input normalization.

Provides run_recon_commands_parallel for executing external recon tools concurrently
with retry support, and normalization helpers from src.core.utils.
"""

from __future__ import annotations

import os
from typing import Any

from src.core.utils import normalize_scope_entry, normalize_url, parse_plain_lines

__all__ = [
    "run_commands_parallel",
    "run_recon_commands_parallel",
    "run_commands_parallel_outcomes",
    "normalize_scope_entry",
    "normalize_url",
    "parse_plain_lines",
    "run_async_in_sync_context",
]


def _get_executor():
    from src.infrastructure.execution_engine.shared_pool import get_recon_executor

    return get_recon_executor()


def run_recon_commands_parallel(
    jobs: list[
        tuple[list[str], str | None]
        | tuple[list[str], str | None, int | None]
        | tuple[list[str], str | None, int | None, Any | None]
    ],
) -> list[str]:
    """Run multiple shell commands in parallel using a thread pool.

    Args:
        jobs: List of command specs. Each can be (command, stdin_text),
            (command, stdin_text, timeout), or (command, stdin_text, timeout, retry_policy).

    Returns:
        List of command outputs (stdout) in job order.
    """
    if not jobs:
        return []

    from src.pipeline.tools import try_command

    normalized_jobs: list[tuple[list[str], str | None, int | None, Any | None]] = []
    for job in jobs:
        if len(job) == 2:
            command, stdin_text = job
            normalized_jobs.append((command, stdin_text, None, None))
        elif len(job) == 3:
            command, stdin_text, timeout = job
            normalized_jobs.append((command, stdin_text, timeout, None))
        else:
            command, stdin_text, timeout, retry_policy = job
            normalized_jobs.append((command, stdin_text, timeout, retry_policy))

    executor = _get_executor()
    futures = [
        executor.submit(try_command, list(command), timeout, stdin_text, retry_policy)
        for command, stdin_text, timeout, retry_policy in normalized_jobs
    ]
    return [future.result() for future in futures]


run_commands_parallel = run_recon_commands_parallel


def _resolve_max_workers(job_count: int) -> int:
    """Resolve the ThreadPool worker count for parallel recon commands.

    The previous implementation hard-coded ``min(8, len(jobs))`` which
    could exhaust file descriptors and DNS resolvers on large-scope
    scans. Operators can now drive this from the environment via
    ``RECON_MAX_PARALLEL_COMMANDS`` (default 8).
    """
    try:
        configured = int(os.environ.get("RECON_MAX_PARALLEL_COMMANDS", "8"))
    except (TypeError, ValueError):
        configured = 8
    return max(1, min(configured, max(1, job_count)))


def run_commands_parallel_outcomes(
    jobs: list[
        tuple[list[str], str | None]
        | tuple[list[str], str | None, int | None]
        | tuple[list[str], str | None, int | None, Any | None]
    ],
) -> list[Any]:
    if not jobs:
        return []

    from src.pipeline.tools import execute_command

    normalized_jobs: list[tuple[list[str], str | None, int | None, Any | None]] = []
    for job in jobs:
        if len(job) == 2:
            command, stdin_text = job
            normalized_jobs.append((command, stdin_text, None, None))
        elif len(job) == 3:
            command, stdin_text, timeout = job
            normalized_jobs.append((command, stdin_text, timeout, None))
        else:
            command, stdin_text, timeout, retry_policy = job
            normalized_jobs.append((command, stdin_text, timeout, retry_policy))

    executor = _get_executor()
    futures = [
        executor.submit(execute_command, list(command), timeout, stdin_text, retry_policy)
        for command, stdin_text, timeout, retry_policy in normalized_jobs
    ]
    return [future.result() for future in futures]


def run_async_in_sync_context(coro: Any) -> Any:
    """Run an async coroutine from a synchronous context, safely handling nested event loops.

    Routes through the shared async bridge to avoid thread/event-loop churn.
    """
    from src.core.utils.async_bridge import run_async_in_sync_context as _bridge_run

    return _bridge_run(coro)
