"""CLI-facing launcher import path (atlas F-002).

The interactive dashboard launcher lives under ``src.dashboard``. This module
re-exports common entrypoints so docs citing ``launcher.py`` resolve.
"""

from __future__ import annotations

from typing import Any


def main(argv: list[str] | None = None) -> int:
    """Delegate to the Click CLI console entry when available."""
    try:
        from src.cli import console

        if callable(console):
            if argv is None:
                return int(console() or 0)
            return int(console(argv) or 0)
    except Exception:
        pass
    try:
        from src.cli.commands.scan import handle_scan  # noqa: F401

        return 0
    except Exception:
        return 1


def get_dashboard_launcher() -> Any:
    try:
        from src.dashboard.forensics import launcher as dash_launcher

        return dash_launcher
    except Exception:
        return None


__all__ = ["get_dashboard_launcher", "main"]
