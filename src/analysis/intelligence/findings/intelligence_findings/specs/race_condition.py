"""Race-condition sensitive flow detected spec."""

from typing import Any

from . import register_spec


def _severity(item: dict[str, Any]) -> str:
    signals = item.get("signals", [])
    return (
        "high"
        if "missing_idempotency_hint" in signals
        and any(
            s.startswith(("path:checkout", "path:payment", "path:book", "path:reservation"))
            for s in signals
        )
        else "medium"
    )


def _description(item: dict[str, Any]) -> str:
    return "Review whether concurrent requests against the same booking, checkout, claim, or coupon flow can change balance, inventory, or reservation state inconsistently."


register_spec(
    (
        "race_condition_signal_analyzer",
        "race_condition",
        _severity,
        "Race-condition sensitive flow detected",
        _description,
    )
)
