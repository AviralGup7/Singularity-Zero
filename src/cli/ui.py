"""Cyber Security Test Pipeline - Unified Command Engine UI and types."""

from __future__ import annotations

from rich.console import Console
from rich.theme import Theme

CYBER_THEME = Theme(
    {
        "info": "cyan",
        "warning": "yellow",
        "error": "bold red",
        "success": "bold green",
        "accent": "bold #00ff41",
    }
)

console = Console(theme=CYBER_THEME)
