"""Incremental CI stage: re-crawl only the URLs that map to git-changed files.

When ``--incremental --base-ref <ref>`` is passed the pipeline restricts
its crawl universe to the union of:

* URLs discovered in the most recent prior run whose ``canonical_key``
  maps to a file changed since ``<ref>`` (read from
  ``priority_scores.json`` of the prior run); and
* Live hosts enumerated by ``git diff --name-only <ref>`` mapped through
  the URL→path heuristic in :func:`_url_matches_changed_path`.

The prior run's recon data is the source of truth for the
URL→file mapping.  When no prior run exists (cold start) the stage is
skipped — a full scan is the correct behaviour for the first CI run on
a target.
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

from src.core.contracts.pipeline_runtime import StageInput, StageOutcome, StageOutput
from src.core.logging.trace_logging import get_pipeline_logger
from src.core.models.stage_result import PipelineContext
from src.pipeline.services.pipeline_helpers import build_stage_input_from_context

logger = get_pipeline_logger(__name__)

_PRIOR_RUN_GLOB = "_launcher/*/recon_manifest.json"
_PRIORITY_SCORES_GLOB = "priority_scores.json"
_URL_PATH_RE = re.compile(r"https?://[^/]+(/[^?#]*)?")


def _find_prior_recon_dir(current_run_dir: Path) -> Path | None:
    """Locate the most recent recon manifest relative to ``current_run_dir``."""
    target_root = current_run_dir.parent
    candidates: list[Path] = []
    for path in target_root.glob(_PRIOR_RUN_GLOB):
        candidates.append(path)
    for path in target_root.rglob(_PRIORITY_SCORES_GLOB):
        candidates.append(path)
    if not candidates:
        return None
    return max(candidates, key=lambda p: p.stat().st_mtime).parent


def _read_priority_scores(run_dir: Path) -> list[dict[str, Any]]:
    """Read the prior run's ``priority_scores.json`` if present."""
    p = run_dir / _PRIORITY_SCORES_GLOB
    if not p.is_file():
        return []
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("Failed to read prior priority_scores.json: %s", exc)
        return []
    if not isinstance(data, list):
        return []
    return [dict(item) for item in data if isinstance(item, Mapping)]


def _git_changed_files(base_ref: str, repo: Path) -> list[str]:
    """Return the list of files changed since ``base_ref``.

    Raises :class:`subprocess.CalledProcessError` if ``git`` is not a
    repo, the ref does not exist, or the working tree is too broken
    to query.
    """
    out = subprocess.run(  # noqa: S603 — args are static, controlled input
        ["git", "diff", "--name-only", base_ref, "HEAD"],  # noqa: S607
        capture_output=True,
        text=True,
        check=True,
        timeout=20,
        cwd=str(repo),
    )
    return [
        line.strip() for line in out.stdout.splitlines() if line.strip()
    ]


def _path_for_url(url: str) -> str | None:
    """Extract the URL path component (without query/fragment)."""
    m = _URL_PATH_RE.match(url)
    if not m:
        return None
    return m.group(1) or "/"


def _stem(path: str) -> str:
    """Return the last path component with its extension stripped."""
    base = path.rsplit("/", 1)[-1]
    if "." in base:
        return base.rsplit(".", 1)[0]
    return base


def _url_matches_changed_path(url: str, changed_paths: Iterable[str]) -> bool:
    """Return True iff ``url``'s path maps to one of the ``changed_paths``.

    The heuristic is intentionally permissive because the inverse mapping
    (file → URL) is application-specific:

    * The URL's last path segment must match the changed file's stem.
    * OR the URL's full path (sans leading ``/``) must be a suffix of the
      changed file path (handles route files like ``routes/api/users.py``).
    """
    url_path = _path_for_url(url)
    if not url_path:
        return False
    url_path = url_path.lstrip("/")
    url_segs = [s for s in url_path.split("/") if s]
    url_basename = url_segs[-1] if url_segs else ""
    for path in changed_paths:
        if not path:
            continue
        file_stem = _stem(path)
        if url_basename and file_stem and url_basename == file_stem:
            return True
        if url_path and (url_path in path or path in url_path):
            return True
    return False


def _filter_url_set(
    urls: Iterable[str],
    changed_paths: Iterable[str],
) -> set[str]:
    paths = list(changed_paths)
    return {u for u in urls if _url_matches_changed_path(u, paths)}


async def run_git_diff_crawl(
    args: Any,
    config: Any,
    ctx: PipelineContext,
    *,
    stage_input: StageInput | None = None,
) -> StageOutput:
    """Restrict the URL set to the files changed since ``--base-ref``."""
    from src.core.logging.pipeline_logging import emit_info

    if stage_input is None:
        # The stage doesn't consume stage_input; only build it when the
        # context actually exposes the attributes ``build_stage_input_from_context``
        # needs.  Direct callers (unit tests, incremental scans invoked
        # from custom orchestrators) may pass a lightweight context.
        if hasattr(ctx, "scope_entries"):
            try:
                stage_input = build_stage_input_from_context(
                    "git_diff_crawl", config, ctx
                )
            except Exception:  # noqa: BLE001
                stage_input = None

    base_ref = getattr(args, "base_ref", None)
    incremental = bool(getattr(args, "incremental", False))

    if not incremental or not base_ref:
        return StageOutput(
            stage_name="git_diff_crawl",
            outcome=StageOutcome.SKIPPED,
            duration_seconds=0.0,
            metrics={"reason": "incremental_disabled" if not incremental else "no_base_ref"},
        )

    run_dir: Path | None = getattr(getattr(ctx, "output_store", None), "run_dir", None)
    if run_dir is None:
        return StageOutput(
            stage_name="git_diff_crawl",
            outcome=StageOutcome.SKIPPED,
            duration_seconds=0.0,
            metrics={"reason": "no_run_dir"},
        )

    repo_root = Path(getattr(args, "repo_root", ".") or ".").resolve()
    prior_dir = _find_prior_recon_dir(run_dir)
    if prior_dir is None:
        emit_info("Incremental scan: no prior run found; falling back to full crawl")
        return StageOutput(
            stage_name="git_diff_crawl",
            outcome=StageOutcome.SKIPPED,
            duration_seconds=0.0,
            metrics={"reason": "no_prior_recon"},
        )

    try:
        changed_paths = _git_changed_files(base_ref, repo_root)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError) as exc:
        logging.getLogger(__name__).warning(
            "Incremental scan: git diff failed (%s); running full crawl", exc
        )
        return StageOutput(
            stage_name="git_diff_crawl",
            outcome=StageOutcome.FAILED,
            duration_seconds=0.0,
            error=str(exc),
            metrics={"reason": "git_diff_failed"},
        )

    if not changed_paths:
        emit_info(f"Incremental scan: no files changed since {base_ref}; nothing to crawl")
        return StageOutput(
            stage_name="git_diff_crawl",
            outcome=StageOutcome.SKIPPED,
            duration_seconds=0.0,
            metrics={"changed_files": 0, "filtered_urls": 0},
        )

    prior_items = _read_priority_scores(prior_dir)
    candidate_urls = {
        str(item.get("url", "")).strip() for item in prior_items if item.get("url")
    }
    candidate_urls.update(
        {
            str(item.get("canonical_key", "")).strip()
            for item in prior_items
            if item.get("canonical_key")
        }
    )
    candidate_urls.discard("")

    filtered = _filter_url_set(candidate_urls, changed_paths)

    ctx.urls = filtered
    ctx.result.urls = filtered
    if hasattr(ctx.result, "priority_urls"):
        existing_priority = set(getattr(ctx.result, "priority_urls", []) or [])
        ctx.result.priority_urls = list(existing_priority & filtered)
    if hasattr(ctx.result, "ranked_priority_urls"):
        ctx.result.ranked_priority_urls = [
            item
            for item in (getattr(ctx.result, "ranked_priority_urls", []) or [])
            if str(item.get("url", "")) in filtered
        ]

    emit_info(
        f"Incremental scan: {len(changed_paths)} file(s) changed since {base_ref}; "
        f"reduced URL set from {len(candidate_urls)} to {len(filtered)}"
    )

    return StageOutput(
        stage_name="git_diff_crawl",
        outcome=StageOutcome.COMPLETED,
        duration_seconds=0.0,
        metrics={
            "changed_files": len(changed_paths),
            "candidate_urls": len(candidate_urls),
            "filtered_urls": len(filtered),
            "base_ref": base_ref,
            "prior_run_dir": str(prior_dir),
        },
        state_delta={
            "urls": filtered,
            "incremental": {
                "base_ref": base_ref,
                "changed_paths": changed_paths,
                "prior_run_dir": str(prior_dir),
            },
        },
    )
