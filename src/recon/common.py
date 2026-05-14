"""Common recon utilities for parallel command execution and input normalization.

Provides run_commands_parallel for executing external recon tools concurrently
with retry support, and re-exports normalization helpers from src.core.utils.
"""

from concurrent.futures import ThreadPoolExecutor

from src.core.utils import normalize_scope_entry, normalize_url, parse_plain_lines
from src.pipeline.tools import RetryPolicy, ToolExecutionOutcome, execute_command, try_command

__all__ = [
    "run_commands_parallel",
    "run_commands_parallel_outcomes",
    "normalize_scope_entry",
    "normalize_url",
    "parse_plain_lines",
    "RetryPolicy",
    "ToolExecutionOutcome",
    "execute_command",
    "try_command",
]


def run_commands_parallel(
    jobs: list[
        tuple[list[str], str | None]
        | tuple[list[str], str | None, int | None]
        | tuple[list[str], str | None, int | None, RetryPolicy | None]
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

    normalized_jobs: list[tuple[list[str], str | None, int | None, RetryPolicy | None]] = []
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

    with ThreadPoolExecutor(max_workers=min(8, len(jobs))) as executor:
        futures = [
            executor.submit(try_command, command, timeout, stdin_text, retry_policy)
            for command, stdin_text, timeout, retry_policy in normalized_jobs
        ]
        return [future.result() for future in futures]


def run_commands_parallel_outcomes(
    jobs: list[
        tuple[list[str], str | None]
        | tuple[list[str], str | None, int | None]
        | tuple[list[str], str | None, int | None, RetryPolicy | None]
    ],
) -> list[ToolExecutionOutcome]:
    if not jobs:
        return []

    normalized_jobs: list[tuple[list[str], str | None, int | None, RetryPolicy | None]] = []
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

    with ThreadPoolExecutor(max_workers=min(8, len(jobs))) as executor:
        futures = [
            executor.submit(execute_command, command, timeout, stdin_text, retry_policy)
            for command, stdin_text, timeout, retry_policy in normalized_jobs
        ]
        return [future.result() for future in futures]
