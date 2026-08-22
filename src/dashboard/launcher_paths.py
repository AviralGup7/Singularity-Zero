"""Canonical on-disk location for dashboard-launched pipeline artifacts.

Writers and readers historically drifted between ``launcher/`` and
``_launcher/``. Recovery, job hrefs, and the artifact router already treat
``_launcher`` as the public path. New launches write there; readers still
accept the legacy directory so older jobs remain recoverable.
"""

from __future__ import annotations

from pathlib import Path

CANONICAL_LAUNCHER_DIRNAME = "_launcher"
LEGACY_LAUNCHER_DIRNAME = "launcher"
LAUNCHER_DIRNAMES: tuple[str, ...] = (CANONICAL_LAUNCHER_DIRNAME, LEGACY_LAUNCHER_DIRNAME)


def launcher_write_dir(output_root: Path, job_id: str) -> Path:
    """Directory new launches must write into."""
    return Path(output_root) / CANONICAL_LAUNCHER_DIRNAME / job_id


def resolve_launcher_dir(output_root: Path, job_id: str) -> Path | None:
    """Return the existing artifact dir for ``job_id``, preferring canonical."""
    root = Path(output_root)
    for name in LAUNCHER_DIRNAMES:
        candidate = root / name / job_id
        if candidate.is_dir():
            return candidate
    return None


def launcher_dir_for(output_root: Path, job_id: str) -> Path:
    """Existing dir if present, otherwise the canonical write target."""
    found = resolve_launcher_dir(output_root, job_id)
    return found if found is not None else launcher_write_dir(output_root, job_id)


def launcher_href_prefix(output_root: Path, job_id: str) -> str:
    found = resolve_launcher_dir(output_root, job_id)
    name = found.parent.name if found is not None else CANONICAL_LAUNCHER_DIRNAME
    return f"/{name}/{job_id}"


def is_launcher_parent(path: Path) -> bool:
    return path.name in LAUNCHER_DIRNAMES
