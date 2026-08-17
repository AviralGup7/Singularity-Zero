"""Regression: generic 'killed' must not be classified as OOM."""

from __future__ import annotations

import pytest

from src.dashboard.error_classification import (
    _classify_memory_issue,
    _classify_stderr,
    _extract_stdout_error_detail,
)


@pytest.mark.unit
def test_generic_killed_is_not_oom() -> None:
    assert _classify_memory_issue("connection killed by peer", 1) is False
    assert _classify_stderr("connection killed by peer", 1) is None
    assert _classify_memory_issue("Killed process 12 (python)", 1) is True
    assert _classify_stderr("out of memory", 1) == "oom_error"
    assert _classify_stderr("boom", 137) == "oom_error"
    assert _classify_stderr("missing", 127) == "executable_not_found"
    assert _classify_stderr("denied", 126) == "permission_denied"
    assert _classify_stderr("stop", 143) == "sigint_or_sigterm"


@pytest.mark.unit
def test_extract_stdout_error_skips_progress_and_truncates() -> None:
    from src.dashboard.registry import PROGRESS_PREFIX

    assert _extract_stdout_error_detail("") == ""
    text = "\n".join(
        [
            f'{PROGRESS_PREFIX}{{"stage": 1}}',
            "INFO starting",
            "ERROR boom happened",
            "Traceback (most recent call last):",
            "FATAL: cannot continue",
        ]
    )
    detail = _extract_stdout_error_detail(text)
    assert "ERROR boom happened" in detail
    assert "Traceback" in detail
    assert "FATAL:" in detail
    assert PROGRESS_PREFIX not in detail
    huge = "error " + ("x" * 600)
    clipped = _extract_stdout_error_detail(huge)
    assert clipped.startswith("...")
    assert len(clipped) == 500
