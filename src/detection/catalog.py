"""Declarative finding-spec catalog.

The 88 spec modules stay under analysis for now. This catalog lists them
without importing analysis, so detection does not depend on that package.
"""

from __future__ import annotations

from pathlib import Path

_SPECS_DIR = (
    Path(__file__).resolve().parents[1] / "analysis" / "intelligence" / "findings" / "specs"
)


def list_finding_spec_keys() -> tuple[str, ...]:
    if not _SPECS_DIR.is_dir():
        return ()
    return tuple(sorted(path.stem for path in _SPECS_DIR.glob("*.py") if path.stem != "__init__"))


def finding_spec_count() -> int:
    return len(list_finding_spec_keys())


__all__ = ["finding_spec_count", "list_finding_spec_keys"]
