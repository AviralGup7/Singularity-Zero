from __future__ import annotations

import re
from pathlib import Path

from src.integration.commands import CATALOG
from src.integration.protocol import HTTP_PREFIX, PROTOCOL_VERSION


def _frontend_commands() -> str:
    return Path("frontend/src/features/bridge/commands.ts").read_text(encoding="utf-8")


def test_command_names_match_typescript() -> None:
    text = _frontend_commands()
    py_names = {spec.key for spec in CATALOG}
    ts_names = set(re.findall(r"name: '([a-z_.]+)'", text))
    assert py_names == ts_names


def test_command_paths_match_typescript() -> None:
    text = _frontend_commands()
    ts_paths = set(re.findall(r"path: '(/api/console/[^']*)'", text))
    py_paths = {spec.path for spec in CATALOG}
    assert py_paths == ts_paths


def test_protocol_version_matches_typescript() -> None:
    text = _frontend_commands()
    assert f"PROTOCOL_VERSION = '{PROTOCOL_VERSION}'" in text
    assert HTTP_PREFIX == "/api/console"
