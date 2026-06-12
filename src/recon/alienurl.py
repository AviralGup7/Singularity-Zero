"""AlienURL aggregator — multi-source archive URL collection.

AlienURL is a 2023+ tool that combines Wayback, Common Crawl, URLScan,
OTX, and AlienVault OTX pulses into a single deduplicated output. It
is the modern replacement for ``gau`` + ``waybackurls`` because it
deduplicates across providers and returns a richer per-URL metadata
set (captured timestamp, source provider, mime type, status code).

This module is a CLI wrapper: when ``alien-url`` (or the alias
``alienurl``) is installed, it delegates to the binary; otherwise it
falls back to a pure-Python fan-out across the individual in-house
collectors registered in this package.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from typing import Any

from src.pipeline.tools import tool_available, try_command
from src.recon.collectors.providers import (
    commoncrawl as _commoncrawl,
)
from src.recon.collectors.providers import (
    otx as _otx,
)
from src.recon.collectors.providers import (
    urlscan as _urlscan,
)
from src.recon.collectors.providers import (
    wayback as _wayback,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# CLI path
# ---------------------------------------------------------------------------


def _resolve_alienurl_binary() -> str | None:
    """Return the name of the alien-url binary on PATH, or None."""
    for candidate in ("alien-url", "alienurl", "alienUrl"):
        if tool_available(candidate):
            return candidate
    return None


def run_alienurl_cli(
    hosts: Iterable[str],
    *,
    timeout_seconds: int = 300,
    extra_args: list[str] | None = None,
) -> set[str]:
    """Run the alien-url CLI to harvest URLs across providers.

    Args:
        hosts: Hostnames to harvest URLs for.
        timeout_seconds: Wall-clock budget for the call.
        extra_args: Additional alien-url flags.

    Returns:
        Set of URLs harvested. Empty when the binary is unavailable.
    """
    binary = _resolve_alienurl_binary()
    if not binary:
        return set()
    candidates = sorted({h for h in hosts if h and h.strip()})
    if not candidates:
        return set()
    args: list[str] = [binary]
    if extra_args:
        args.extend(extra_args)
    args.extend(candidates)
    output = try_command(args, timeout=max(1, int(timeout_seconds)))
    return {line.strip() for line in (output or "").splitlines() if line.strip()}


# ---------------------------------------------------------------------------
# Pure-Python fan-out fallback
# ---------------------------------------------------------------------------


def run_aggregated_archive(
    hosts: Iterable[str],
    *,
    timeout_seconds: int = 60,
    per_host_limit: int = 500,
    progress_callback: Any | None = None,
) -> tuple[set[str], dict[str, Any]]:
    """Run all in-house archive collectors in parallel and dedupe results.

    The function is the "AlienURL does not exist" fallback. It returns
    the same shape as :func:`run_alienurl_cli` plus a meta dict so the
    orchestrator can log per-provider statistics.

    Args:
        hosts: Hostnames to query.
        timeout_seconds: Per-collector wall-clock budget.
        per_host_limit: Per-collector per-host URL cap.
        progress_callback: Optional progress hook.

    Returns:
        Tuple of (urls, meta). ``meta`` keys: ``status``,
        ``duration_seconds``, ``new_urls``, ``providers``.
    """
    import time
    from concurrent.futures import ThreadPoolExecutor

    hosts_list = sorted({h for h in hosts if h and h.strip()})
    if not hosts_list:
        return set(), {"status": "empty", "duration_seconds": 0.0, "new_urls": 0}

    started = time.monotonic()
    discovered: set[str] = set()
    provider_meta: dict[str, dict[str, Any]] = {}

    def _run(provider: str, fn: Any) -> None:
        try:
            urls, meta = fn(
                hosts_list,
                timeout_seconds=timeout_seconds,
                per_host_limit=per_host_limit,
            )
        except Exception as exc:  # noqa: BLE001
            logger.debug("AlienURL provider %s failed: %s", provider, exc)
            provider_meta[provider] = {"status": "error", "new_urls": 0}
            return
        provider_meta[provider] = meta
        before = len(discovered)
        discovered.update(urls)
        if progress_callback is not None and urls:
            try:
                progress_callback(provider, len(discovered) - before)
            except Exception:  # noqa: BLE001, S110
                pass

    providers = (
        ("wayback", _wayback.collect_for_hosts),
        ("commoncrawl", _commoncrawl.collect_for_hosts),
        ("urlscan", _urlscan.collect_for_hosts),
        ("otx", _otx.collect_for_hosts),
    )

    with ThreadPoolExecutor(max_workers=len(providers)) as ex:
        futures = [ex.submit(_run, name, fn) for name, fn in providers]
        for fut in futures:
            fut.result()

    duration = round(time.monotonic() - started, 1)
    return discovered, {
        "status": "ok" if discovered else "empty",
        "duration_seconds": duration,
        "new_urls": len(discovered),
        "providers": provider_meta,
    }


# ---------------------------------------------------------------------------
# Top-level entry point
# ---------------------------------------------------------------------------


def collect_archive_urls(
    hosts: Iterable[str],
    *,
    timeout_seconds: int = 300,
    per_host_limit: int = 500,
    progress_callback: Any | None = None,
) -> set[str]:
    """High-level entry point: prefer alien-url CLI, fall back to fan-out.

    Args:
        hosts: Hostnames to query.
        timeout_seconds: Per-call wall-clock budget.
        per_host_limit: Per-collector per-host cap (fallback only).
        progress_callback: Optional progress hook (fallback only).

    Returns:
        Set of URLs harvested from all configured providers.
    """
    if _resolve_alienurl_binary():
        urls = run_alienurl_cli(hosts, timeout_seconds=timeout_seconds)
        if urls:
            return urls
    urls, _ = run_aggregated_archive(
        hosts,
        timeout_seconds=timeout_seconds,
        per_host_limit=per_host_limit,
        progress_callback=progress_callback,
    )
    return urls


__all__ = [
    "collect_archive_urls",
    "run_aggregated_archive",
    "run_alienurl_cli",
]
