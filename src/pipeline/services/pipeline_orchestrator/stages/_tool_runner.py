"""Async wrappers for scanner subprocesses.

Scanner CLIs (Trivy, Checkov, Grype, Semgrep, Gitleaks) commonly return
exit code 1 when they *found issues*. Codes >= 2 or < 0 are treated as
tool failures so a crashed scan cannot be reported as a clean COMPLETED.
"""

from __future__ import annotations

import asyncio
import subprocess
from collections.abc import Sequence
from pathlib import Path


def is_scanner_crash(returncode: int | None) -> bool:
    """True when the CLI failed to run, as opposed to reporting findings."""
    if returncode is None:
        return True
    return returncode < 0 or returncode >= 2


async def run_scanner(
    cmd: Sequence[str],
    *,
    timeout: int,
    cwd: str | Path | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run ``cmd`` off the event loop so long scans do not freeze the orchestrator."""

    def _run() -> subprocess.CompletedProcess[str]:
        return subprocess.run(  # noqa: S603
            list(cmd),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            cwd=str(cwd) if cwd is not None else None,
        )

    return await asyncio.to_thread(_run)
