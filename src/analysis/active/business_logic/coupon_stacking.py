"""Coupon stacking probes.

Applies the same coupon N times to the cart and checks whether the
server accepts a discount beyond the spec-defined redemption limit.
"""

from __future__ import annotations

import logging
from typing import Any

from src.analysis.helpers import classify_endpoint, endpoint_base_key, endpoint_signature

ResponseCache = Any

logger = logging.getLogger(__name__)

_MAX_REDEMPTIONS_TO_TEST: int = 5

_COUPON_PATH_HINTS = {"/cart", "/basket", "/checkout", "/apply-coupon", "/coupon", "/discount"}


def _path_suffix(url: str) -> str:
    from urllib.parse import urlparse

    return urlparse(url).path.lower()


def _looks_like_coupon_endpoint(url: str) -> bool:
    path = _path_suffix(url)
    return any(hint in path for hint in _COUPON_PATH_HINTS)


def _build_redundant_coupon_payload(base: dict[str, Any], iterations: int) -> list[dict[str, Any]]:
    code = str(base.get("coupon_code") or base.get("coupon") or base.get("code") or "STACKTEST")
    return [
        {
            **base,
            "coupon_code": code,
            "iteration": idx,
            "_redundant_applied": idx > 0,
        }
        for idx in range(iterations)
    ]


def _accepted(response_body: str) -> bool:
    lowered = response_body.lower()
    return "invalid" not in lowered and "already used" not in lowered and "expired" not in lowered


def _probe_confidence(issues: list[str]) -> float:
    values = [0.60, 0.70, 0.80, 0.88]
    idx = min(len(issues) - 1, len(values) - 1)
    return values[idx]


def coupon_stacking_probe(
    priority_urls: list[dict[str, Any]],
    response_cache: Any | None = None,
    *,
    client: Any = None,
    sandbox_session: Any = None,
    limit: int = 12,
    timeout_seconds: float = 5.0,
) -> list[dict[str, Any]]:
    """Apply coupon code N times and flag when all succeed."""
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()

    for item in priority_urls:
        if len(findings) >= limit:
            break
        url = str(item.get("url", "") if isinstance(item, dict) else item).strip()
        if not url or not _looks_like_coupon_endpoint(url):
            continue
        endpoint_key = endpoint_signature(url)
        if endpoint_key in seen:
            continue
        seen.add(endpoint_key)

        base_response = response_cache.get(url) if response_cache else None
        body_text = str(base_response.get("body_text", "")) if base_response else ""
        base_payload: dict[str, Any] = {"coupon_code": "STACKTEST"}

        successes = 0
        poster = getattr(client, "post", None) if client is not None else None
        if poster is None:
            # Cached baseline cannot prove stacking; skip rather than false-positive.
            logger.debug("coupon stacking skipped for %s: no HTTP client", url)
            continue
        for seq in _build_redundant_coupon_payload(base_payload, _MAX_REDEMPTIONS_TO_TEST):
            try:
                response = poster(url, json=seq, timeout=timeout_seconds)
                if hasattr(response, "__await__"):
                    logger.debug("coupon stacking skipped for %s: async client", url)
                    successes = 0
                    break
                body = getattr(response, "text", None)
                if body is None:
                    body = str(getattr(response, "body", "") or body_text)
                if _accepted(str(body)):
                    successes += 1
            except Exception:
                logger.debug("coupon stacking probe failed for %s", url, exc_info=True)
                break

        if successes > 1:
            findings.append(
                {
                    "url": url,
                    "endpoint_key": endpoint_key,
                    "endpoint_base_key": endpoint_base_key(url),
                    "endpoint_type": classify_endpoint(url),
                    "issues": ["coupon_stacking_allowed"],
                    "probe_type": "business_logic.coupon_stacking",
                    "severity": "high",
                    "confidence": _probe_confidence(["coupon_stacking_allowed"]),
                    "evidence": {
                        "coupon_code": base_payload.get("coupon_code"),
                        "successes": successes,
                        "sandbox_mode": True,
                    },
                }
            )

    findings.sort(key=lambda item: (-item.get("confidence", 0), item.get("url", "")))
    return findings[:limit]
