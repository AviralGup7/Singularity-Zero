"""Drift-triggered focused rescan.

The :class:`src.recon.drift_detection.DriftDetector` already computes
the set of newly-observed subdomains, live hosts, and URLs between
two consecutive recon runs. This module acts on those deltas:

* When **only a few new subdomains** appear (e.g. less than 5% of
  the historical set), the rescan should focus on the new entries —
  not re-scan the whole scope.
* When **a large number of new subdomains** appear (more than 20% of
  the historical set), the rescan should still focus but with a
  higher parallelism budget.
* When **new live hosts** appear with no corresponding new URL
  discoveries, the rescan should add the new hosts to the URL
  collector but skip the other phases.
* When the drift report contains no new entries, no rescan is
  needed.

The :func:`build_focused_rescan_plan` function returns a structured
plan that the orchestrator can execute. Each plan is a dict with
``phases`` (the list of stages to re-run), ``scope_hosts`` (the
hosts to focus on), and ``priority_score`` (a 0-1 estimate of how
"interesting" the rescan is likely to be).
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def build_focused_rescan_plan(
    drift_report: dict[str, Any],
    *,
    previous_run_meta: dict[str, Any] | None = None,
    small_drift_threshold: float = 0.05,
    large_drift_threshold: float = 0.20,
) -> dict[str, Any]:
    """Build a focused-rescan plan from a drift report.

    Args:
        drift_report: Output of
            :func:`src.recon.drift_detection.DriftDetector.compute_drift`.
        previous_run_meta: Optional metadata from the previous run
            (used to size the rescan and compute the priority score).
        small_drift_threshold: Fraction of the historical set below
            which drift is considered "small" and triggers a
            minimum-overhead focused rescan.
        large_drift_threshold: Fraction above which the rescan
            is treated as "large" and the orchestrator is given
            permission to allocate a higher parallelism budget.

    Returns:
        Dict with the following keys:

        * ``phases``: list of phase names to re-run, in order. May be
          empty when no rescan is needed.
        * ``scope_hosts``: the union of new subdomains, new live
          hosts, and hosts that produced new URLs. Deduplicated.
        * ``priority_score``: 0-1 estimate of the rescan's likely
          value. ``1.0`` is "we have lots of new live hosts and
          URLs that should be re-probed with full nuclei".
        * ``reason``: human-readable explanation of the plan.
    """
    if not drift_report or not drift_report.get("has_drift", False):
        return {
            "phases": [],
            "scope_hosts": set(),
            "priority_score": 0.0,
            "reason": "no drift detected; rescan unnecessary",
        }

    deltas = drift_report.get("deltas", {}) or {}
    new_subdomains = set(deltas.get("subdomains", {}).get("added", []) or [])
    new_live_hosts = set(deltas.get("live_hosts", {}).get("added", []) or [])
    new_urls = set(deltas.get("urls", {}).get("added", []) or [])

    # Hosts that produced new URLs — extracted by urlparse so we can
    # re-scope the rescan to just those hosts.
    from urllib.parse import urlparse

    hosts_from_urls: set[str] = set()
    for url in new_urls:
        try:
            host = urlparse(url).hostname
        except ValueError:
            host = ""
        if host:
            hosts_from_urls.add(host.lower())

    scope_hosts = new_subdomains | new_live_hosts | hosts_from_urls

    # Decide the phase list
    previous_total = 0
    if previous_run_meta is not None:
        previous_total = int(
            previous_run_meta.get("total_subdomains")
            or previous_run_meta.get("subdomain_count")
            or 0
        )
    if previous_total <= 0:
        previous_total = max(
            len(new_subdomains) + len(new_live_hosts),
            1,
        )

    ratio = len(new_subdomains) / max(1, previous_total)
    if ratio >= large_drift_threshold:
        # Large drift: re-run live host probing, url collection,
        # nuclei (this is more than just "a typo in DNS"; something
        # structural is changing).
        phases = ["subdomain_enum_focused", "live_probe", "url_collection", "nuclei"]
        priority = 0.95
        reason = (
            f"large drift detected ({len(new_subdomains)} new subdomains, "
            f"~{ratio:.0%} of historical set); full focused rescan"
        )
    elif ratio >= small_drift_threshold:
        phases = ["subdomain_enum_focused", "live_probe", "url_collection", "nuclei"]
        priority = 0.7
        reason = (
            f"moderate drift detected ({len(new_subdomains)} new subdomains); "
            "focused rescan of the new scope"
        )
    else:
        # Small drift: just re-probe the new live hosts with nuclei
        # and re-collect URLs. We do NOT re-run subdomain enumeration
        # because the new entries are likely a small DNS-only change
        # (a new CI runner, a new dev environment, etc.).
        phases = ["live_probe", "url_collection", "nuclei"]
        priority = 0.45
        reason = (
            f"small drift detected ({len(new_subdomains)} new subdomains, "
            f"{len(new_live_hosts)} new live hosts); minimal focused rescan"
        )

    # Bonus: if we see new URLs without new hosts, the *content* of
    # existing hosts has changed. That's still worth a nuclei
    # pass but not a full re-probe.
    if new_urls and not new_live_hosts and not new_subdomains:
        phases = ["url_collection", "nuclei"]
        priority = 0.55
        reason = "new URLs on existing hosts; targeted nuclei rescan"

    return {
        "phases": phases,
        "scope_hosts": scope_hosts,
        "priority_score": priority,
        "reason": reason,
        "delta_summary": {
            "new_subdomains": len(new_subdomains),
            "new_live_hosts": len(new_live_hosts),
            "new_urls": len(new_urls),
        },
    }


__all__ = ["build_focused_rescan_plan"]
