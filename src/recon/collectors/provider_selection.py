"""Shared provider-selection and tool-gating logic for the in-house URL
collectors.

Historically the in-house aggregator (``aggregator.py``) and the
streaming aggregator (``aggregator_stream.py``) both implemented their
own copy of the same tool-enabled checks.  When a new provider is
added or a flag renamed, both files must be updated in lockstep.

This module is the single source of truth.  Both aggregators call
:func:`select_enabled_providers` to obtain the ordered list of
providers they should run.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from src.recon.collectors.providers import commoncrawl, crawler, otx, urlscan, wayback


@dataclass(frozen=True)
class ProviderSpec:
    """Description of a single configured provider to invoke.

    Attributes:
        name: Short identifier used in logs and stage metadata
            (``"wayback"``, ``"commoncrawl"`` …).
        func: The ``collect_for_hosts`` callable for that provider.
        timeout_seconds: Per-call HTTP timeout.
        per_host_limit: Maximum records to fetch per hostname.
        max_workers: Concurrency hint for the provider.  ``None`` means
            the provider manages its own concurrency.
    """

    name: str
    func: Callable[..., tuple[set[str], Any]]
    timeout_seconds: int
    per_host_limit: int
    max_workers: int | None = None


def _tool_enabled(config: Any, name: str, default: bool = True) -> bool:
    """Return True if ``config.tools[name]`` is truthy.  Absent keys
    resolve to ``default`` (``True`` for backwards compatibility)."""
    tools = getattr(config, "tools", None) or {}
    return bool(tools.get(name, default))


def _tool_timeout(config: Any, name: str, default: int) -> int:
    cfg = getattr(config, name, None) or {}
    return int(cfg.get("timeout_seconds", default))


def _per_host_limit(config: Any, name: str, default: int) -> int:
    filters = getattr(config, "filters", None) or {}
    if name == "crawler":
        cfg = getattr(config, "katana", None) or {}
        return int(
            filters.get("crawler_max_pages_per_host", cfg.get("max_pages_per_host", default))
        )
    if name == "crawler_workers":
        cfg = getattr(config, "katana", None) or {}
        return int(filters.get("crawler_workers", cfg.get("workers", default)))
    if filters:
        return int(filters.get("per_host_archive_limit", default))
    return default


def select_enabled_providers(config: Any) -> list[ProviderSpec]:
    """Return the ordered list of in-house providers enabled in ``config``.

    Order is important: wayback/commoncrawl come first because they are
    the highest-signal passive archives, crawler last because it is the
    most expensive.
    """
    specs: list[ProviderSpec] = []
    if _tool_enabled(config, "waybackurls", True):
        specs.append(
            ProviderSpec(
                name="wayback",
                func=wayback.collect_for_hosts,
                timeout_seconds=_tool_timeout(config, "waybackurls", 120),
                per_host_limit=_per_host_limit(config, "waybackurls", 1000),
            )
        )
    if _tool_enabled(config, "commoncrawl", True):
        specs.append(
            ProviderSpec(
                name="commoncrawl",
                func=commoncrawl.collect_for_hosts,
                timeout_seconds=_tool_timeout(config, "commoncrawl", 120),
                per_host_limit=_per_host_limit(config, "commoncrawl", 1000),
            )
        )
    if _tool_enabled(config, "urlscan", True):
        specs.append(
            ProviderSpec(
                name="urlscan",
                func=urlscan.collect_for_hosts,
                timeout_seconds=_tool_timeout(config, "urlscan", 30),
                per_host_limit=_per_host_limit(config, "urlscan", 100),
            )
        )
    if _tool_enabled(config, "otx", True):
        specs.append(
            ProviderSpec(
                name="otx",
                func=otx.collect_for_hosts,
                timeout_seconds=_tool_timeout(config, "otx", 30),
                per_host_limit=_per_host_limit(config, "otx", 100),
            )
        )
    if _tool_enabled(config, "katana", True):
        specs.append(
            ProviderSpec(
                name="crawler",
                func=crawler.collect_for_hosts,
                timeout_seconds=_tool_timeout(config, "katana", 30),
                per_host_limit=_per_host_limit(config, "crawler", 12),
                max_workers=_per_host_limit(config, "crawler_workers", 6),
            )
        )
    return specs


__all__ = ["ProviderSpec", "select_enabled_providers"]
