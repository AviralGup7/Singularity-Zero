"""Expand a URL/domain IOC into related lookup keys."""

from __future__ import annotations

from src.intel.ioc import Indicator, IndicatorKind, classify_indicator, host_from_url, related_indicators


def expand(raw: object) -> list[Indicator]:
    indicator = classify_indicator(raw) if not isinstance(raw, Indicator) else raw
    items = related_indicators(indicator)
    if indicator.kind is IndicatorKind.DOMAIN:
        parts = indicator.normalized().split(".")
        if len(parts) > 2:
            items.append(classify_indicator(".".join(parts[-2:])))
    if indicator.kind is IndicatorKind.URL:
        host = host_from_url(indicator.value)
        items.extend(expand(host))
    unique: list[Indicator] = []
    seen: set[str] = set()
    for item in items:
        if item.kind is IndicatorKind.UNKNOWN:
            continue
        key = f"{item.kind}:{item.normalized()}"
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)
    return unique
