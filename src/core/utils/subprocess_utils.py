"""Shared subprocess-related utility functions.

Consolidates duplicated helpers (SHELL_META, _clean_env, _coerce_output_text,
_get_creationflags) used across tool execution, frontier process pool, and
analysis automation.
"""

from __future__ import annotations

import re
import subprocess
import sys

SHELL_META = re.compile(r"[;|&`$\n\r]")


def _get_creationflags() -> int:
    if sys.platform.startswith("win"):
        return subprocess.CREATE_NO_WINDOW
    return 0


def _clean_env(env: dict[str, str] | None = None) -> dict[str, str]:
    if env is None:
        return {}
    clean: dict[str, str] = {}
    for k, v in env.items():
        try:
            k_str = str(k)
            v_str = str(v)
            k_str.encode("utf-8")
            v_str.encode("utf-8")
            clean[k_str] = v_str
        except (UnicodeEncodeError, UnicodeDecodeError):
            continue
    return clean


def _coerce_output_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="ignore")
    return value
