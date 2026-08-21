"""Single index for analysis/checks (active + passive + exposure)."""

from __future__ import annotations

from pathlib import Path

_ROOT = Path(__file__).resolve().parent


def _module_stems(folder: Path) -> tuple[str, ...]:
    if not folder.is_dir():
        return ()
    names: list[str] = []
    for path in folder.rglob("*.py"):
        if path.name.startswith("_") or path.name == "__init__.py":
            continue
        names.append(path.stem)
    return tuple(sorted(set(names)))


def list_active_checks() -> tuple[str, ...]:
    return _module_stems(_ROOT / "active")


def list_passive_checks() -> tuple[str, ...]:
    return _module_stems(_ROOT / "passive")


def list_exposure_checks() -> tuple[str, ...]:
    return _module_stems(_ROOT / "exposure")


def list_all_checks() -> tuple[str, ...]:
    return tuple(sorted(set(list_active_checks() + list_passive_checks() + list_exposure_checks())))


__all__ = [
    "list_active_checks",
    "list_all_checks",
    "list_exposure_checks",
    "list_passive_checks",
]
