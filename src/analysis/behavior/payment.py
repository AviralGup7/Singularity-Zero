"""Payment flow intelligence for detecting payment-related endpoints and providers.

Analyzes URLs, responses, and parameters to identify payment processing flows,
detect payment providers (Stripe, PayPal, etc.), and surface payment-related
security considerations.
"""

import re
from typing import Any
from urllib.parse import urlparse

from src.analysis.helpers import (
    classify_endpoint,
    endpoint_base_key,
    endpoint_signature,
    meaningful_query_pairs,
)

PAYMENT_PATH_TOKENS = {
    "cart": ("cart", "basket"),
    "checkout": ("checkout", "pay", "payment"),
    "billing": ("billing", "invoice", "receipt"),
    "subscription": ("subscription", "plan", "renew"),
    "refund": ("refund", "chargeback", "dispute"),
    "wallet": ("wallet", "gift-card"),
    "webhook": ("webhook", "callback"),
}
PAYMENT_PARAM_TOKENS = {
    "amount",
    "currency",
    "coupon",
    "discount",
    "invoice",
    "invoice_id",
    "line_item",
    "order",
    "order_id",
    "payment_intent",
    "payment_method",
    "plan",
    "price",
    "product",
    "promo",
    "quantity",
    "refund_id",
    "session_id",
    "subscription",
    "subscription_id",
}
PAYMENT_PROVIDER_PATTERNS = {
    "stripe": re.compile(r"stripe|paymentintent|client_secret|checkout\.stripe", re.IGNORECASE),
    "paypal": re.compile(r"paypal|braintree", re.IGNORECASE),
    "adyen": re.compile(r"adyen", re.IGNORECASE),
    "checkout_com": re.compile(r"checkout\.com|cko-", re.IGNORECASE),
    "razorpay": re.compile(r"razorpay", re.IGNORECASE),
    "square": re.compile(r"squareup|square", re.IGNORECASE),
    "klarna": re.compile(r"klarna", re.IGNORECASE),
}
AMOUNT_RE = re.compile(r'"(?:amount|subtotal|total|price)"\s*:\s*(\d+(?:\.\d+)?)', re.IGNORECASE)


def payment_flow_intelligence(
    urls: set[str], responses: list[dict[str, Any]], limit: int = 80
) -> list[dict[str, Any]]:
    response_map = {str(item.get("url", "")).strip(): item for item in responses if item.get("url")}
    findings = []
    seen: set[str] = set()
    for url in sorted(urls):
        signals, stage = _payment_signals_for_url(url)
        response = response_map.get(url)
        provider_hits = payment_provider_detection([response] if response else [])
        providers = provider_hits[0]["providers"] if provider_hits else []
        if response:
            signals.extend(_payment_signals_for_response(response))
        signals = sorted(set(signals))
        if not signals:
            continue
        dedupe = endpoint_signature(url)
        if dedupe in seen:
            continue
        seen.add(dedupe)
        query_keys = sorted(
            {key for key, _ in meaningful_query_pairs(url) if key in PAYMENT_PARAM_TOKENS}
        )[:10]
        findings.append(
            {
                "url": url,
                "endpoint_key": endpoint_signature(url),
                "endpoint_base_key": endpoint_base_key(url),
                "endpoint_type": classify_endpoint(url),
                "payment_stage": stage,
                "signals": signals,
                "providers": providers,
                "payment_parameters": query_keys,
                "score": len(signals) + len(query_keys) + (2 if providers else 0),
                "hint_message": _payment_hint(stage, providers, query_keys),
            }
        )
    findings.sort(
        key=lambda item: (
            -int(item["score"]) if isinstance(item["score"], (int, float)) else 0,
            item["url"],
        )
    )
    return findings[:limit]


def payment_provider_detection(
    responses: list[dict[str, Any]], limit: int = 60
) -> list[dict[str, Any]]:
    findings = []
    for response in responses:
        if not response:
            continue
        body = response.get("body_text") or ""
        combined = " ".join(
            [
                str(response.get("content_type", "")),
                body[:4000],
                _headers_string(response.get("headers") or {}),
            ]
        )
        providers = [
            label
            for label, pattern in PAYMENT_PROVIDER_PATTERNS.items()
            if pattern.search(combined)
        ]
        if not providers:
            continue
        url = str(response.get("url", "")).strip()
        findings.append(
            {
                "url": url,
                "endpoint_key": endpoint_signature(url),
                "endpoint_base_key": endpoint_base_key(url),
                "endpoint_type": classify_endpoint(url),
                "providers": sorted(set(providers)),
            }
        )
    findings.sort(key=lambda item: (-len(item["providers"]), item["url"]))
    return findings[:limit]


def _payment_signals_for_url(url: str) -> tuple[list[str], str]:
    parsed = urlparse(url)
    path = parsed.path.lower()
    query_pairs = meaningful_query_pairs(url)
    signals = []
    stage = "payment"
    for label, tokens in PAYMENT_PATH_TOKENS.items():
        if any(token in path for token in tokens):
            signals.append(f"path_stage:{label}")
            if stage == "payment":
                stage = label
    for key, _ in query_pairs:
        if key in PAYMENT_PARAM_TOKENS:
            signals.append(f"payment_param:{key}")
    return signals, stage


def _payment_signals_for_response(response: dict[str, Any]) -> list[str]:
    body = response.get("body_text") or ""
    lowered = body.lower()
    signals = []
    if any(
        token in lowered
        for token in (
            "subtotal",
            "discount",
            "shipping",
            "tax",
            "line_items",
            "payment_intent",
            "invoice",
            "subscription",
            "refund",
        )
    ):
        signals.append("payment_response_schema")
    if AMOUNT_RE.search(body):
        signals.append("amount_field")
    if any(pattern.search(lowered) for pattern in PAYMENT_PROVIDER_PATTERNS.values()):
        signals.append("provider_reference")
    return signals


def _payment_hint(stage: str, providers: list[str], params: list[str]) -> str:
    provider_text = ", ".join(providers) if providers else "embedded processor references"
    if stage == "checkout":
        return f"Review checkout amount, currency, discount, and item identifiers, then compare client-side versus server-side enforcement around {provider_text}."
    if stage == "billing":
        return "Check whether invoice, receipt, or billing history endpoints leak other users' documents or totals."
    if stage == "subscription":
        return "Inspect plan, price, and subscription identifiers for insecure upgrades, downgrades, or cross-account access."
    if stage == "refund":
        return "Validate refund and dispute references carefully to confirm ownership and state transitions."
    if params:
        return f"Replay the payment-related parameters one at a time ({', '.join(params[:4])}) and compare pricing, ownership, and authorization behavior."
    return "Inspect the payment-oriented flow for amount tampering, coupon abuse, invoice exposure, and provider token leakage."


def _headers_string(headers: dict[str, Any]) -> str:
    return " ".join(f"{key}:{value}" for key, value in headers.items())
