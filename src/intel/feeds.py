"""Feed registry — which TI connectors are actually configured.

Clients live in ``src.intelligence.feeds``. This module is the pipeline
stage contract so VirusTotal / OTX / MISP / Shodan are first-class and
discoverable without importing every connector.
"""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class FeedDescriptor:
    key: str
    label: str
    env_var: str
    configured: bool


_FEEDS: tuple[tuple[str, str, str], ...] = (
    ("virustotal", "VirusTotal", "VT_API_KEY"),
    ("otx", "AlienVault OTX", "OTX_API_KEY"),
    ("misp", "MISP", "MISP_API_KEY"),
    ("shodan", "Shodan", "SHODAN_API_KEY"),
    ("cve", "CVE sync", "NVD_API_KEY"),
)


def _env_set(name: str) -> bool:
    if name == "VT_API_KEY":
        return bool(
            os.environ.get("VT_API_KEY", "").strip()
            or os.environ.get("VIRUSTOTAL_API_KEY", "").strip()
        )
    return bool(os.environ.get(name, "").strip())


def list_feeds() -> tuple[FeedDescriptor, ...]:
    return tuple(
        FeedDescriptor(key=key, label=label, env_var=env, configured=_env_set(env))
        for key, label, env in _FEEDS
    )


def configured_feed_keys() -> tuple[str, ...]:
    return tuple(feed.key for feed in list_feeds() if feed.configured)


def is_feed_configured(key: str) -> bool:
    needle = str(key or "").strip().lower()
    return any(feed.key == needle and feed.configured for feed in list_feeds())
