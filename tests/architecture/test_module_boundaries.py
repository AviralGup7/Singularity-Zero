"""Static import-boundary checks for the extracted domain packages."""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2] / "src"


def _imported_modules(package: str) -> set[str]:
    root = ROOT / package.replace(".", "/")
    found: set[str] = set()
    for path in root.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    found.add(alias.name)
            elif isinstance(node, ast.ImportFrom) and node.module:
                found.add(node.module)
    return found


def _forbids(package: str, *banned: str) -> None:
    imported = _imported_modules(package)
    for name in banned:
        offenders = [item for item in imported if item == name or item.startswith(name + ".")]
        assert not offenders, f"{package} must not import {name}: {offenders}"


def test_detection_does_not_import_analysis() -> None:
    _forbids("detection", "src.analysis")


def test_auth_does_not_import_dashboard_or_fastapi() -> None:
    _forbids("auth", "src.dashboard", "fastapi")


def test_jobs_does_not_import_dashboard() -> None:
    _forbids("jobs", "src.dashboard")


def test_notifications_only_depends_on_auth() -> None:
    _forbids("notifications", "src.dashboard", "src.pipeline", "fastapi")


def test_resilience_does_not_import_pipeline() -> None:
    _forbids("resilience", "src.pipeline", "src.dashboard")
