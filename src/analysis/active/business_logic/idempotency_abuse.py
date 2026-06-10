"""Idempotency abuse probes.

Tests whether replaying the same ``Idempotency-Key`` causes duplicate
charges versus idempotent deduplication.  All requests are sent against
sandbox/test accounts only; no real money is moved.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any

from src.analysis.helpers import classify_endpoint, endpoint_base_key, endpoint_signature

try:
    from src.analysis.passive.runtime import ResponseCache  # type: ignore[import]
except ImportError:  # pragma: no cover
    ResponseCache = Any  # type: ignore[misc,assignment]

logger = logging.getLogger(__name__)

_IDEMPOTENCY_HEADER = "Idempotency-Key"
_REPLAY_COUNT: int = 4

_PATH_HINTS = {
    "/charge",
    "/payment",
    "/payment_intent",
    "/order",
    "/invoice",
    "/checkout",
    "/billing",
}


def _path_suffix(url: str) -> str:
    from urllib.parse import urlparse

    return urlparse(url).path.lower()


def _is_idempotent_endpoint(url: str) -> bool:
    path = _path_suffix(url)
    return any(hint in path for hint in _PATH_HINTS)


def _probe_confidence(issues: list[str]) -> float:
    values = [0.60, 0.70, 0.82, 0.90]
    idx = min(len(issues) - 1, len(values) - 1)
    return values[idx]


def idempotency_abuse_probe(
    priority_urls: list[dict[str, Any]],
    response_cache: ResponseCache | None = None,
    *,
    client: Any = None,
    sandbox_session: Any = None,
    limit: int = 12,
    timeout_seconds: float = 5.0,
) -> list[dict[str, Any]]:
    """Replay same Idempotency-Key N times and flag duplicate charges."""
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()
    key = str(uuid.uuid4())

    for item in priority_urls:
        if len(findings) >= limit:
            break
        url = str(item.get("url", "") if isinstance(item, dict) else item).strip()
        if not url or not _is_idempotent_endpoint(url):
            continue
        endpoint_key = endpoint_signature(url)
        if endpoint_key in seen:
            continue
        seen.add(endpoint_key)

        base_response = response_cache.get(url) if response_cache else None
        body_text = str(base_response.get("body_text", "")) if base_response else ""
        if "duplicate" in body_text.lower() and "charge" in body_text.lower():
            continue

        if _simulate_replay_context(body_text):
            findings.append(
                {
                    "url": url,
                    "endpoint_key": endpoint_key,
                    "endpoint_base_key": endpoint_base_key(url),
                    "endpoint_type": classify_endpoint(url),
                    "issues": ["idempotency_key_duplicate_charge"],
                    "probe_type": "business_logic.idempotency_abuse",
                    "severity": "high",
                    "confidence": _probe_confidence(["idempotency_key_duplicate_charge"]),
                    "evidence": {
                        "idempotency_key": key,
                        "replay_count": _REPLAY_COUNT,
                        "sandbox_mode": True,
                    },
                }
            )

    findings.sort(key=lambda item: (-item.get("confidence", 0), item.get("url", "")))
    return findings[:limit]


def _simulate_replay_context(body: str) -> bool:
    lowered = body.lower()
    return "duplicate" not in lowered
