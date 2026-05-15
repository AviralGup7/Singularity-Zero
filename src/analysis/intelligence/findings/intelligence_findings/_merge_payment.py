"""Merge payment flow findings into unified findings list."""

from typing import Any


def merge_payment(
    analysis_results: dict[str, list[dict[str, Any]]],
    priority_scores: dict[str, int],
    seen: set[tuple[str, str, str, str]],
    findings: list[dict[str, Any]],
) -> None:
    from ._merge import _finding

    for item in analysis_results.get("payment_flow_intelligence", []):
        severity = (
            "medium"
            if item.get("payment_stage") in {"checkout", "billing", "subscription", "refund"}
            else "low"
        )
        f = _finding(
            "payment_flow_intelligence",
            "payment",
            severity,
            "Payment flow surface detected",
            item.get("url", ""),
            item,
            priority_scores.get(item.get("url", ""), 0),
            item.get(
                "hint_message",
                "Inspect the payment-oriented flow for amount, coupon, and ownership controls.",
            ),
            seen,
        )
        if f:
            findings.append(f)
