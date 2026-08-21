"""Operator watchlist of IOCs."""

from __future__ import annotations

from src.intel.ioc import Indicator, classify_indicator


class Watchlist:
    def __init__(self) -> None:
        self._items: dict[str, Indicator] = {}

    def add(self, raw: object) -> Indicator:
        indicator = classify_indicator(raw)
        self._items[f"{indicator.kind}:{indicator.normalized()}"] = indicator
        return indicator

    def contains(self, raw: object) -> bool:
        indicator = classify_indicator(raw)
        return f"{indicator.kind}:{indicator.normalized()}" in self._items

    def matching(self, blob: str) -> list[Indicator]:
        from src.intel.ioc import extract_indicators

        found = extract_indicators(blob)
        hits = [item for item in found if self.contains(item.value)]
        if hits:
            return hits
        return [item for item in self.values() if item.normalized() in blob.lower()]

    def __len__(self) -> int:
        return len(self._items)

    def values(self) -> list[Indicator]:
        return list(self._items.values())
