"""URL weighting and prioritisation for the URL cap stage.

The previous recon stage truncated the URL set with a single
``filter_similar`` call that kept ``max_results`` entries from the
front of the (sorted) union. This is biased in several ways:

* Recent (and high-signal) endpoints from archive sources get sorted
  lexicographically and may be dropped.
* Sensitive endpoints like ``/admin/``, ``/api/users/{id}`` look
  identical to noise once sorted.
* ``?debug=1`` and similar low-signal URLs fill the cap before the
  interesting ones do.

This module provides a deterministic, content-aware weighting that
the URL collector can apply before the cap. Each URL receives a
weight derived from:

* **Path depth and shape** — endpoints with parameters
  (``/api/users/{id}``) score higher than static assets.
* **Path keywords** — admin, api, oauth, internal, debug, etc. push
  the URL to the top.
* **File extensions** — .json, .xml, .config, .log, .sql, .bak score
  higher than .html / .css.
* **Source preference** — URLs from the local live-host probe are
  preferred over archive URLs (which may be 5 years old).
* **Recency hints** — when a source provides a timestamp (e.g. CDX
  capture date) more recent URLs win.

The output is a sorted URL list that ``filter_similar`` then trims
to the configured ``max_results``.
"""

from __future__ import annotations

import logging
import math
from collections.abc import Iterable
from urllib.parse import parse_qsl, urlparse

logger = logging.getLogger(__name__)


# Token weights for the keyword boost. Higher = more interesting.
_KEYWORD_WEIGHTS: dict[str, float] = {
    "admin": 4.0,
    "internal": 3.0,
    "api": 2.5,
    "graphql": 3.0,
    "v1": 1.0,
    "v2": 1.2,
    "v3": 1.4,
    "user": 2.5,
    "users": 2.5,
    "account": 2.5,
    "auth": 3.0,
    "oauth": 3.0,
    "token": 3.0,
    "session": 2.0,
    "login": 2.0,
    "debug": 2.5,
    "swagger": 2.0,
    "openapi": 2.0,
    "actuator": 2.5,
    "metrics": 2.0,
    "health": 1.0,
    "env": 2.0,
    "trace": 1.5,
    "config": 2.0,
    "console": 2.5,
    "upload": 2.5,
    "download": 1.5,
    "file": 1.5,
    "document": 1.0,
    "search": 1.0,
    "id": 1.0,
    "order": 1.5,
    "payment": 4.0,
    "billing": 4.0,
    "invoice": 3.0,
    "checkout": 3.5,
    "cart": 2.0,
    "secret": 4.0,
    "key": 2.5,
    "credential": 4.0,
    "password": 4.0,
    "private": 3.0,
    "public": 0.5,
    "static": -1.5,
    "assets": -1.5,
    "css": -2.0,
    "js": -1.0,
    "image": -1.5,
    "img": -1.5,
    "fonts": -2.0,
}

# File extension weights. Negative weights push the URL toward the
# end of the cap (noise); positive weights push toward the front.
_EXT_WEIGHTS: dict[str, float] = {
    "json": 2.0,
    "xml": 1.5,
    "yaml": 1.5,
    "yml": 1.5,
    "config": 3.0,
    "ini": 2.0,
    "log": 2.5,
    "sql": 3.0,
    "bak": 3.0,
    "old": 1.5,
    "env": 3.0,
    "properties": 2.0,
    "txt": 0.5,
    "csv": 1.0,
    "pdf": 1.0,
    "doc": 1.0,
    "docx": 0.5,
    "xls": 1.0,
    "xlsx": 0.5,
    "zip": 1.0,
    "tar": 0.5,
    "gz": 0.5,
    "html": -0.5,
    "htm": -0.5,
    "css": -2.0,
    "js": -1.0,
    "mjs": -0.5,
    "map": 0.0,
    "png": -2.0,
    "jpg": -2.0,
    "jpeg": -2.0,
    "gif": -2.0,
    "svg": -1.5,
    "ico": -1.5,
    "woff": -2.0,
    "woff2": -2.0,
    "ttf": -2.0,
    "eot": -2.0,
    "mp4": -1.5,
    "webm": -1.5,
    "mp3": -1.5,
    "wav": -1.5,
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def _extension(path: str) -> str:
    """Return the lowercased file extension of *path* (no dot), or empty string."""
    last_dot = path.rfind(".")
    last_slash = max(path.rfind("/"), path.rfind("?"))
    if last_dot <= last_slash or last_dot == -1:
        return ""
    return path[last_dot + 1 : last_slash if last_slash > last_dot else None].lower()


def score_url(url: str) -> float:
    """Compute the weight for a single URL.

    Higher scores are more interesting. The score is the sum of
    keyword boosts, extension boost, parameter boost, and path-depth
    adjustment. The function never raises; an unparseable URL
    receives a score of 0.0.
    """
    try:
        parsed = urlparse(url)
    except ValueError:
        return 0.0

    path_lower = (parsed.path or "").lower()
    if not path_lower:
        return 0.0

    score = 0.0

    # Path depth: 1-2 segments = noise, 3+ = interesting
    depth = sum(1 for seg in path_lower.split("/") if seg)
    if depth >= 4:
        score += 1.5
    elif depth >= 3:
        score += 0.8
    elif depth == 1:
        score -= 0.5

    # Keyword boost
    for keyword, weight in _KEYWORD_WEIGHTS.items():
        if keyword in path_lower:
            score += weight

    # Extension boost
    ext = _extension(path_lower)
    if ext:
        score += _EXT_WEIGHTS.get(ext, 0.0)

    # Parameter boost: more params = more interesting
    try:
        params = parse_qsl(parsed.query, keep_blank_values=True)
    except ValueError:
        params = []
    score += min(2.0, 0.3 * len(params))

    # URL-encoded template placeholders are highly interesting
    if "{param}" in url or "FUZZ" in url or "%s" in url:
        score += 1.5

    # Trailing slashes / home pages are noise
    if path_lower in {"/", "/index", "/index.html", "/home"}:
        score -= 1.0

    return score


def sort_urls_by_weight(urls: Iterable[str]) -> list[str]:
    """Sort URLs in descending order of weight, breaking ties alphabetically.

    The result is stable, deterministic, and ready to feed into
    :func:`filter_similar` for the final cap.
    """
    decorated = [(-score_url(u), u) for u in {u for u in urls if u}]
    decorated.sort()
    return [u for _, u in decorated]


def trim_urls(
    urls: Iterable[str],
    *,
    max_results: int,
) -> list[str]:
    """Sort + dedupe + cap the URL list using the weighting function.

    Args:
        urls: Raw URL set.
        max_results: Maximum number of URLs to keep.

    Returns:
        Sorted list of URLs, length at most ``max_results``.
    """
    if max_results <= 0:
        return []
    sorted_urls = sort_urls_by_weight(urls)
    if len(sorted_urls) <= max_results:
        return sorted_urls
    return sorted_urls[:max_results]


# ---------------------------------------------------------------------------
# Recency scoring
# ---------------------------------------------------------------------------


def recency_score(
    *,
    captured_at: str | None = None,
    now: float | None = None,
) -> float:
    """Convert a Wayback-style timestamp string to a 0.0-1.0 recency score.

    Args:
        captured_at: ISO-8601 timestamp, e.g. ``"20240315120000"`` or
            ``"2024-03-15T12:00:00Z"``.
        now: Override the current epoch (for tests).

    Returns:
        Float in ``[0.0, 1.0]``. ``1.0`` is the most recent; ``0.0``
        is anything older than 5 years or unparseable.
    """
    if not captured_at:
        return 0.0
    import datetime as _dt

    if now is None:
        now = _dt.datetime.now(_dt.timezone.utc).timestamp()  # noqa: UP017 — Python 3.10 compat
    cleaned = captured_at.strip().rstrip("Z")
    for fmt in (
        "%Y%m%d%H%M%S",
        "%Y%m%d%H%M",
        "%Y%m%d",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d",
    ):
        try:
            captured_dt = _dt.datetime.strptime(cleaned, fmt)
            if captured_dt.tzinfo is None:
                captured_dt = captured_dt.replace(tzinfo=_dt.timezone.utc)  # noqa: UP017 — Python 3.10 compat
            break
        except ValueError:
            continue
    else:
        return 0.0
    captured_epoch = captured_dt.timestamp()
    age_seconds = max(0.0, now - captured_epoch)
    age_years = age_seconds / (365.25 * 24 * 3600)
    if age_years >= 5:
        return 0.0
    return 1.0 - (age_years / 5.0)


def combined_score(
    url: str,
    *,
    captured_at: str | None = None,
    source_weight: float = 1.0,
) -> float:
    """Score a URL combining keyword/path/extension weight with recency.

    Args:
        url: The URL to score.
        captured_at: Optional capture timestamp (Wayback CDX-style).
        source_weight: Multiplier applied to the keyword score
            (e.g. 1.5 for in-house collectors, 0.8 for archive).

    Returns:
        Float, higher is more interesting.
    """
    base = score_url(url)
    recency = recency_score(captured_at=captured_at)
    return base * source_weight + recency


# Math import is here to avoid surprising import order in the rest of
# the module (kept for any future use of math.log-style scoring).
_ = math.log  # pragma: no cover

__all__ = [
    "combined_score",
    "recency_score",
    "score_url",
    "sort_urls_by_weight",
    "trim_urls",
]
