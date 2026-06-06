
"""Host fingerprinting utilities.

Extracted from ``src.recon.live_hosts``.  Provides host metadata extraction
helpers used during live-host discovery.
"""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urlparse

from src.core.models import Config, DEFAULT_USER_AGENT
from src.core.utils.url_validation import is_safe_url
from src.recon.common import normalize_url

logger = logging.getLogger(__name__)


def _host_from_url(value: str) -> str:
    parsed = urlparse(str(value or "").strip())
    hostname = (parsed.hostname or "").strip().lower()
    port = getattr(parsed, "port", None)
    if port:
        return f"{hostname}:{port}"
    return hostname


def _normalized_probe_hosts(subdomains: set[str]) -> list[str]:
    return sorted({entry.strip().lower() for entry in subdomains if entry and entry.strip()})


def classify_response(result: dict[str, Any]) -> dict[str, Any]:
    """Classify a probe result with standard metadata fingerprints."""
    url = normalize_url(str(result.get("url", "") or ""))
    if not url:
        return {}
    return {
        "url": url,
        "status_code": result.get("status_code"),
        "source": result.get("source", "python-probe"),
        "resolved_host": result.get("resolved_host", _host_from_url(url)),
        "scheme": urlparse(url).scheme,
        "host": _host_from_url(url),
    }
