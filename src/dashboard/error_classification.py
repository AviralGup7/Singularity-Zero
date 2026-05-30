"""Subprocess error and stdout/stderr classification helpers for dashboard jobs."""

from src.dashboard.registry import PROGRESS_PREFIX

# Common memory/OOM signatures in subprocess errors
_OOM_SIGNATURES = [
    "out of memory",
    "oom-killer",
    "cannot allocate memory",
    "killed",
]


def _classify_memory_issue(stderr_content: str, returncode: int) -> bool:
    """Detect if the subprocess failed due to Out-Of-Memory (OOM) conditions."""
    if returncode in (137, 247):  # Standard exit codes for SIGKILL (128+9) or similar OOM kills
        return True
    content_lower = stderr_content.lower()
    return any(sig in content_lower for sig in _OOM_SIGNATURES)


def _classify_stderr(stderr_content: str, returncode: int) -> str | None:
    """Classify a stderr content and return a failure reason classification code."""
    if _classify_memory_issue(stderr_content, returncode):
        return "oom_error"
    if returncode == 127:
        return "executable_not_found"
    if returncode == 126:
        return "permission_denied"
    if returncode in (130, 143):
        return "sigint_or_sigterm"
    return None


def _truncate_lines(lines: list[str], *, limit: int = 6) -> list[str]:
    """Deduplicate and truncate a list of log/error lines to a maximum limit."""
    deduped: list[str] = []
    for line in lines:
        text = str(line or "").strip()
        if not text or text in deduped:
            continue
        deduped.append(text)
    return deduped[-limit:]


def _extract_stdout_error_detail(stdout_text: str) -> str:
    """Extract recent traceback or error lines from stdout stream, ignoring progress JSON."""
    if not stdout_text:
        return ""
    stdout_lines = stdout_text.splitlines()
    error_lines = [
        line
        for line in stdout_lines
        if line.strip()
        and (
            not line.strip().startswith(PROGRESS_PREFIX)
            and (
                "error" in line.lower()
                or "exception" in line.lower()
                or "traceback" in line.lower()
                or "fatal" in line.lower()
                or line.lstrip().startswith("FATAL:")
            )
        )
    ]
    if not error_lines:
        return ""
    detail = "\n".join(error_lines[-10:])
    if len(detail) > 500:
        detail = "..." + detail[-497:]
    return detail
