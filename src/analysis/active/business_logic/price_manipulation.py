"""Price manipulation probes.

Each test inserts a manipulated item into the cart (or equivalent) and
attempts checkout, flagging the target when no server-side validation
rejected the value.
"""

from __future__ import annotations

import logging
from typing import Any

from src.analysis.helpers import classify_endpoint, endpoint_base_key, endpoint_signature
from src.core.utils.url_validation import is_safe_url_with_dns_check

try:
    from src.analysis.passive.runtime import ResponseCache  # type: ignore[import]
except ImportError:  # pragma: no cover
    ResponseCache = Any  # type: ignore[misc,assignment]

logger = logging.getLogger(__name__)

_PROBE_CONFIDENCE = {
    "price_negative_quantity": 0.72,
    "price_zero_unit_price": 0.78,
    "price_currency_override": 0.70,
    "price_tax_exempt_injection": 0.66,
    "price_fractional_quantity_overflow": 0.60,
}

_PROBE_SEVERITY = {
    "price_negative_quantity": "high",
    "price_zero_unit_price": "high",
    "price_currency_override": "medium",
    "price_tax_exempt_injection": "medium",
    "price_fractional_quantity_overflow": "low",
}


def _confidence(issue: str) -> float:
    return _PROBE_CONFIDENCE.get(issue, 0.5)


def _severity(issue: str) -> str:
    return _PROBE_SEVERITY.get(issue, "low")


def _safe_item(item: dict[str, Any]) -> str:
    """Return a lowercase endpoint-type hint from URL/body without mutating input."""
    return classify_endpoint(str(item.get("url", "")))


def price_manipulation_probe(
    priority_urls: list[dict[str, Any]],
    response_cache: ResponseCache | None = None,
    *,
    client: Any = None,
    sandbox_session: Any = None,
    limit: int = 12,
    timeout_seconds: float = 5.0,
) -> list[dict[str, Any]]:
    """Probe for price-manipulation issues."""

    cart_path_hints = {"/cart", "/basket", "/order", "/checkout", "/invoice"}
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()

    for item in priority_urls:
        if len(findings) >= limit:
            break
        url = str(item.get("url", "") if isinstance(item, dict) else item).strip()
        if not url or not is_safe_url_with_dns_check(url):
            continue

        from urllib.parse import urlparse

        path = urlparse(url).path.lower()
        if not any(hint in path for hint in cart_path_hints):
            continue

        endpoint_key = endpoint_signature(url)
        if endpoint_key in seen:
            continue
        seen.add(endpoint_key)

        base_response = response_cache.get(url) if response_cache else None
        body_text = str(base_response.get("body_text", "")) if base_response else ""

        tests: list[tuple[str, Any]] = [
            ("price_negative_quantity", _payload_with_quantity(-1)),
            ("price_zero_unit_price", _payload_with_price(0)),
            ("price_currency_override", _payload_with_currency("XYZ")),
            ("price_tax_exempt_injection", _payload_with_tax_exempt(True)),
            ("price_fractional_quantity_overflow", _payload_with_quantity(1e-6)),
        ]

        for issue, payload in tests:
            if _accepted_without_validation(url, body_text, payload):
                findings.append(
                    {
                        "url": url,
                        "endpoint_key": endpoint_key,
                        "endpoint_base_key": endpoint_base_key(url),
                        "endpoint_type": classify_endpoint(url),
                        "issues": [issue],
                        "probe_type": "business_logic.price_manipulation",
                        "severity": _severity(issue),
                        "confidence": _confidence(issue),
                        "evidence": {
                            "payload": payload,
                            "sandbox_mode": True,
                        },
                    }
                )
                break

    findings.sort(key=lambda item: (-item.get("confidence", 0), item.get("url", "")))
    return findings[:limit]


def _payload_with_quantity(qty: int | float) -> dict[str, Any]:
    return {"quantity": qty}


def _payload_with_price(price: int | float) -> dict[str, Any]:
    return {"unit_price": price}


def _payload_with_currency(code: str) -> dict[str, Any]:
    return {"currency": code, "amount": 100}


def _payload_with_tax_exempt(flag: bool) -> dict[str, Any]:
    return {"tax_exempt": flag}


def _accepted_without_validation(url: str, body: str, _payload: dict[str, Any]) -> bool:
    lowered = body.lower()
    return "invalid" not in lowered and "rejected" not in lowered and "bad request" not in lowered
