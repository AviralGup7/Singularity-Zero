"""Finding exporters. Pipeline reporting is the only caller."""

from __future__ import annotations

from pathlib import Path

_PLATFORMS = Path(__file__).resolve().parent / "platforms"
_SKIP = frozenset({"__init__", "base"})


def list_exporter_platforms() -> tuple[str, ...]:
    if not _PLATFORMS.is_dir():
        return ()
    return tuple(sorted(path.stem for path in _PLATFORMS.glob("*.py") if path.stem not in _SKIP))


__all__ = ["list_exporter_platforms"]
