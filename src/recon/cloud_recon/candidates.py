"""Bucket and Cloud Run candidate generation."""

from __future__ import annotations

from urllib.parse import urlparse

from src.recon.cloud_recon.constants import (
    _GCP_CLOUD_RUN_REGION_TEMPLATES,
    _GCP_CLOUD_RUN_SERVICE_HINTS,
)

_SUFFIXES = [
    "",
    "-backup",
    "-backups",
    "-assets",
    "-public",
    "-private",
    "-prod",
    "-production",
    "-dev",
    "-development",
    "-staging",
    "-stage",
    "-test",
    "-data",
    "-database",
    "-storage",
    "-s3",
    "-bucket",
    "-photos",
    "-images",
    "-logs",
    "-billing",
    "-internal",
    "-cloud",
    "-shares",
    "-files",
    "-archive",
    "-temp",
]


def _extract_core_name(target: str) -> str:
    parsed = urlparse(target if "://" in target else f"https://{target}")
    domain = parsed.hostname or parsed.path or target
    return domain.split(".")[0].lower().strip()


def generate_candidates(target: str) -> list[str]:
    """Generate smart storage bucket candidates based on target domain.

    Args:
        target: Target domain or name (e.g. 'example.com')

    Returns:
        List of unique bucket name candidates.
    """
    core_name = _extract_core_name(target)
    if not core_name:
        return []
    core_names = {core_name}
    if "-" in core_name:
        core_names.add(core_name.replace("-", ""))
    candidates = set()
    for name in core_names:
        for suffix in _SUFFIXES:
            candidates.add(f"{name}{suffix}")
            if suffix.startswith("-"):
                dot_suffix = suffix.replace("-", ".")
                candidates.add(f"{name}{dot_suffix}")
    return sorted(list(candidates))


def enumerate_cloud_run_candidates(target: str) -> list[str]:
    """Generate candidate GCP Cloud Run URLs for the target brand."""
    core_name = _extract_core_name(target)
    if not core_name:
        return []
    candidates: set[str] = set()
    for hint in _GCP_CLOUD_RUN_SERVICE_HINTS:
        for region_tpl in _GCP_CLOUD_RUN_REGION_TEMPLATES:
            candidates.add(f"{core_name}-{hint}{region_tpl}")
            candidates.add(f"{core_name}{region_tpl}")
    return sorted(candidates)


def build_cloud_run_1st_gen_candidates(
    target: str, *, enable_cloud_run_enum: bool = True,
) -> list[str]:
    core_name = _extract_core_name(target)
    if not core_name:
        return []
    candidates: set[str] = set()
    if enable_cloud_run_enum:
        for hint in _GCP_CLOUD_RUN_SERVICE_HINTS:
            for region_tpl in _GCP_CLOUD_RUN_REGION_TEMPLATES:
                candidates.add(f"{core_name}-{hint}{region_tpl}")
                candidates.add(f"{core_name}{region_tpl}")
    return sorted(candidates)


def build_cloud_run_2nd_gen_candidates(
    target: str,
    *,
    enable_cloud_run_enum: bool = True,
    gcp_regions: tuple[str, ...] | None = None,
) -> list[str]:
    from src.recon.cloud_recon.constants import _DEFAULT_GCP_REGIONS

    core_name = _extract_core_name(target)
    if not core_name:
        return []
    regions = gcp_regions or _DEFAULT_GCP_REGIONS
    candidates: set[str] = set()
    if enable_cloud_run_enum:
        for region in regions:
            candidates.add(f"{core_name}-{region}-uc.a.run.app")
            candidates.add(f"{core_name}-{region}.a.run.app")
            for h in _GCP_CLOUD_RUN_SERVICE_HINTS:
                candidates.add(f"{core_name}-{h}-{region}-uc.a.run.app")
                candidates.add(f"{core_name}-{h}-{region}.a.run.app")
    return sorted(candidates)
