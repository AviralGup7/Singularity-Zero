"""Cyber Security Test Pipeline — unified security orchestration framework."""

from __future__ import annotations

import io
import sys

# ---------------------------------------------------------------------------
# Windows console encoding fix — must run before any module writes to stdout/stderr
# ---------------------------------------------------------------------------
if sys.platform.startswith("win") and "pytest" not in sys.modules:
    _needs_wrap = False
    for _stream in (sys.stdout, sys.stderr):
        if hasattr(_stream, "encoding") and getattr(_stream, "encoding", "").lower() not in (
            "utf-8",
            "utf8",
            "utf_8",
        ):
            _needs_wrap = True
            break
    if _needs_wrap:
        for _stream_name in ("stdout", "stderr"):
            _stream = getattr(sys, _stream_name)
            if hasattr(_stream, "buffer") and not isinstance(_stream, io.TextIOWrapper):
                setattr(
                    sys,
                    _stream_name,
                    io.TextIOWrapper(_stream.buffer, encoding="utf-8", errors="replace"),
                )

__version__ = "3.1.0"

__all__: list[str] = []
