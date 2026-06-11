"""Preview deployment enumeration for Vercel / Netlify / Railway / Render / Fly.io.

Modern CI/CD pipelines create per-branch preview deployments with
hostnames that follow a deterministic pattern:

* Vercel:    ``<project>-git-<branch>-<user>.vercel.app`` and the older
  ``<project>-<hash>.vercel.app`` form.
* Netlify:   ``<hash>--<project>.netlify.app`` (deploy preview) and
  ``<branch>--<project>.netlify.app``.
* Railway:   ``<project>-pr-<pr_number>.up.railway.app``.
* Render:    ``<project>-pr-<pr_number>.onrender.com``.
* Fly.io:    ``<app>-pr-<pr_number>.<region>.fly.dev`` (less common).

The previous recon module only knew about the base service hostnames
(``*.vercel.app`` etc.) for the *takeover* check, not for *finding*
preview deployments. This module generates the candidate preview
hostnames from a list of (project, branch) tuples and probes them in
parallel.
"""

from __future__ import annotations

import json
import logging
import os
import re
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor
from typing import Any
from urllib.parse import urlparse

import requests

from src.recon.url_validation import is_safe_url

logger = logging.getLogger(__name__)

DEFAULT_PROBE_TIMEOUT = 5
DEFAULT_PROBE_CONCURRENCY = 10

USER_AGENT = "cyber-pipeline/2.0 (preview-deployments)"


# ---------------------------------------------------------------------------
# Candidate generation
# ---------------------------------------------------------------------------


def vercel_preview_candidates(
    project: str,
    branches: Iterable[str] = (),
    users: Iterable[str] = (),
) -> set[str]:
    """Generate Vercel preview hostnames for *project*."""
    candidates: set[str] = set()
    project = (project or "").strip().lower()
    if not project:
        return candidates
    for branch in branches or ():
        branch = branch.strip().lower()
        if not branch:
            continue
        candidates.add(f"{project}-git-{branch}.vercel.app")
        candidates.add(f"{project}--git-{branch}.vercel.app")
    for user in users or ():
        user = user.strip().lower()
        if not user:
            continue
        for branch in branches or ["main"]:
            candidates.add(f"{project}-git-{branch}-{user}.vercel.app")
    return candidates


def netlify_preview_candidates(
    project: str,
    branches: Iterable[str] = (),
    hashes: Iterable[str] = (),
) -> set[str]:
    """Generate Netlify preview hostnames for *project*."""
    candidates: set[str] = set()
    project = (project or "").strip().lower()
    if not project:
        return candidates
    for branch in branches or ():
        branch = branch.strip().lower().replace("/", "-")
        if not branch:
            continue
        candidates.add(f"{branch}--{project}.netlify.app")
    for hash_value in hashes or ():
        hash_value = hash_value.strip().lower()
        if hash_value:
            candidates.add(f"{hash_value}--{project}.netlify.app")
    return candidates


def railway_pr_candidates(project: str, pr_numbers: Iterable[int]) -> set[str]:
    """Generate Railway preview hostnames for *project*."""
    candidates: set[str] = set()
    project = (project or "").strip().lower()
    if not project:
        return candidates
    for pr in pr_numbers or ():
        try:
            candidates.add(f"{project}-pr-{int(pr)}.up.railway.app")
        except (TypeError, ValueError):
            continue
    return candidates


def render_pr_candidates(project: str, pr_numbers: Iterable[int]) -> set[str]:
    """Generate Render preview hostnames for *project*."""
    candidates: set[str] = set()
    project = (project or "").strip().lower()
    if not project:
        return candidates
    for pr in pr_numbers or ():
        try:
            candidates.add(f"{project}-pr-{int(pr)}.onrender.com")
        except (TypeError, ValueError):
            continue
    return candidates


_FLY_IO_REGIONS: tuple[str, ...] = ("iad", "fra", "ams", "lax", "hkg", "syd")


def fly_io_pr_candidates(project: str, pr_numbers: Iterable[int]) -> set[str]:
    candidates: set[str] = set()
    project = (project or "").strip().lower()
    if not project:
        return candidates
    for pr in pr_numbers or ():
        try:
            pr_int = int(pr)
        except (TypeError, ValueError):
            continue
        for region in _FLY_IO_REGIONS:
            candidates.add(f"{project}-pr-{pr_int}.{region}.fly.dev")
    return candidates


def amplify_preview_candidates(project: str, branches: Iterable[str] = ()) -> set[str]:
    candidates: set[str] = set()
    project = (project or "").strip().lower()
    if not project:
        return candidates
    for branch in branches or ():
        branch = branch.strip().lower().replace("/", "-")
        if not branch:
            continue
        candidates.add(f"{branch}.{project}.amplifyapp.com")
    return candidates


def firebase_preview_candidates(project: str, channels: Iterable[str] = ()) -> set[str]:
    candidates: set[str] = set()
    project = (project or "").strip().lower().replace(".", "-")
    if not project:
        return candidates
    for channel in channels or ():
        channel = channel.strip().lower().replace("/", "-")
        if not channel:
            continue
        candidates.add(f"{channel}.{project}.web.app")
    return candidates


def azure_static_apps_candidates(project: str, branches: Iterable[str] = ()) -> set[str]:
    candidates: set[str] = set()
    project = (project or "").strip().lower().replace("_", "-")
    if not project:
        return candidates
    for branch in branches or ():
        branch = branch.strip().lower().replace("/", "-")
        if not branch:
            continue
        candidates.add(f"{project}-{branch}.azurestaticapps.net")
    return candidates


_DETERMINISTIC_BRANCHES: tuple[str, ...] = (
    "main",
    "master",
    "develop",
    "dev",
    "feature",
    "hotfix",
    "release",
    "staging",
    "test",
    "qa",
)


def _guess_project_name_from_inputs(
    git_remote: str | None = None,
    package_json_path: str | None = None,
    repo_slug: str | None = None,
) -> str:
    if repo_slug:
        slug = repo_slug.strip().lower().replace("_", "-")
        if slug:
            return slug.split("/")[-1]
    if git_remote:
        remote = git_remote.strip().lower().rstrip("/")
        if remote:
            for prefix in ("https://github.com/", "git@github.com:", "https://gitlab.com/"):
                if remote.startswith(prefix):
                    remote = remote[len(prefix) :]
                    break
            remote = remote.split("/")[-1]
            if remote.endswith(".git"):
                remote = remote[:-4]
            if remote:
                return remote
    if package_json_path and os.path.isfile(package_json_path):
        try:
            with open(package_json_path, encoding="utf-8") as fh:
                data = json.load(fh)
            if isinstance(data, dict) and isinstance(data.get("name"), str):
                name = data["name"].strip().lower().split("/")[-1].replace("_", "-")
                if name:
                    return str(name)
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("Operation failed in preview_deployments.py: %s", exc, exc_info=True)  # noqa: BLE001
    return ""


# ---------------------------------------------------------------------------
# Probe
# ---------------------------------------------------------------------------


def _probe_preview_host(
    host: str,
    *,
    timeout: int = DEFAULT_PROBE_TIMEOUT,
) -> dict[str, Any] | None:
    """Return a small dict for *host* if it responds, else None."""
    if not host or not is_safe_url(f"https://{host}"):
        return None
    try:
        resp = requests.get(
            f"https://{host}",
            timeout=max(2, int(timeout)),
            allow_redirects=True,
            headers={"User-Agent": USER_AGENT},
        )
    except requests.RequestException:
        return None
    if resp.status_code >= 500:
        return None
    return {
        "host": host,
        "url": f"https://{host}",
        "status_code": resp.status_code,
        "title": _extract_title(resp.text or ""),
        "server": resp.headers.get("server", ""),
    }


def _extract_title(html: str) -> str:
    if not html:
        return ""

    match = re.search(r"<title[^>]*>([^<]+)</title>", html, re.IGNORECASE)
    return match.group(1).strip() if match else ""


def discover_preview_deployments(
    candidates: Iterable[str],
    *,
    timeout: int = DEFAULT_PROBE_TIMEOUT,
    max_workers: int = DEFAULT_PROBE_CONCURRENCY,
    progress_callback: Any | None = None,
) -> list[dict[str, Any]]:
    """Probe a list of candidate preview hostnames in parallel.

    Args:
        candidates: Hostnames (no scheme) to probe.
        timeout: Per-probe timeout in seconds.
        max_workers: Max concurrent HTTP probes.
        progress_callback: Optional ``callable(processed, total)``.

    Returns:
        List of dicts ``{host, url, status_code, title, server}`` for
        every host that responded with a 2xx/3xx/4xx. Hosts returning
        5xx or timing out are skipped.
    """
    host_list = sorted({h for h in candidates if h and h.strip()})
    if not host_list:
        return []

    results: list[dict[str, Any]] = []
    total = len(host_list)
    processed = 0
    with ThreadPoolExecutor(max_workers=max(1, min(max_workers, total))) as ex:
        futures = {ex.submit(_probe_preview_host, h, timeout=timeout): h for h in host_list}
        for fut in futures:
            try:
                probe = fut.result()
            except Exception as exc:  # noqa: BLE001
                logger.debug("Preview probe failed: %s", exc)
                probe = None
            processed += 1
            if progress_callback is not None:
                try:
                    progress_callback(processed, total)
                except Exception:  # noqa: BLE001
                    pass
            if probe is not None:
                results.append(probe)
    return results


# ---------------------------------------------------------------------------
# Convenience helpers
# ---------------------------------------------------------------------------


def all_candidates_for_project(
    project: str,
    *,
    branches: Iterable[str] = (),
    users: Iterable[str] = (),
    netlify_hashes: Iterable[str] = (),
    pr_numbers: Iterable[int] = (),
    amplify_branch_overrides: Iterable[str] | None = None,
    firebase_channels: Iterable[str] | None = None,
    fly_regions: Iterable[str] | None = None,
) -> set[str]:
    """Return the union of preview hostnames for *project* across providers."""
    branch_list = list(
        dict.fromkeys(
            [b for b in branches or () if b and str(b).strip()] or list(_DETERMINISTIC_BRANCHES)
        )
    )
    candidates: set[str] = set()
    candidates.update(vercel_preview_candidates(project, branch_list, users))
    candidates.update(netlify_preview_candidates(project, branch_list, netlify_hashes))
    candidates.update(railway_pr_candidates(project, pr_numbers))
    candidates.update(render_pr_candidates(project, pr_numbers))
    candidates.update(fly_io_pr_candidates(project, pr_numbers))
    candidates.update(amplify_preview_candidates(project, amplify_branch_overrides or branch_list))
    candidates.update(firebase_preview_candidates(project, firebase_channels or branch_list))
    candidates.update(azure_static_apps_candidates(project, branch_list))
    return candidates


def parse_host_from_url(url: str) -> str:
    """Extract the hostname from a URL (best-effort)."""
    if not url:
        return ""
    parsed = urlparse(url if "://" in url else f"https://{url}")
    return (parsed.hostname or "").lower()


__all__ = [
    "all_candidates_for_project",
    "amplify_preview_candidates",
    "azure_static_apps_candidates",
    "discover_preview_deployments",
    "firebase_preview_candidates",
    "fly_io_pr_candidates",
    "netlify_preview_candidates",
    "parse_host_from_url",
    "railway_pr_candidates",
    "render_pr_candidates",
    "vercel_preview_candidates",
]
