"""Automated filtering system that applies rules without user input.

Rules are defined in configuration and applied automatically
to filter out false positives and irrelevant findings.
"""

import re
from dataclasses import dataclass
from typing import Any


@dataclass
class FilterRule:
    """A single filter rule for automated finding filtering."""

    name: str
    field: str
    match_type: str
    value: str
    inverse: bool = False

    def matches(self, item: dict[str, Any]) -> bool:
        """Check if item matches this rule."""
        field_value = self._get_field(item)
        if field_value is None:
            return False

        result = self._check_match(field_value)
        return not result if self.inverse else result

    def _get_field(self, item: dict[str, Any]) -> str | None:
        """Extract field value from item."""
        if self.field == "url":
            return str(item.get("url", ""))
        elif self.field == "body":
            return str(item.get("response_body", ""))
        elif self.field == "headers":
            return str(item.get("request_headers", {}))
        elif self.field == "method":
            return str(item.get("method", ""))
        elif self.field == "status":
            return str(item.get("status_code", ""))
        return None

    def _check_match(self, value: str) -> bool:
        """Check if value matches the rule."""
        if self.match_type == "contains":
            return self.value.lower() in value.lower()
        elif self.match_type == "not_contains":
            return self.value.lower() not in value.lower()
        elif self.match_type == "regex":
            return bool(re.search(self.value, value, re.IGNORECASE))
        elif self.match_type == "equals":
            return value.lower() == self.value.lower()
        return False


class AutoFilterEngine:
    """Automated filtering engine that applies rules without user input.

    Rules are defined in configuration and applied automatically.
    """

    def __init__(self) -> None:
        self._rules: list[FilterRule] = []
        self._logic: str = "AND"

    def add_rule(self, rule: FilterRule) -> None:
        """Add a filter rule."""
        self._rules.append(rule)

    def set_logic(self, logic: str) -> None:
        """Set AND/OR logic for rule evaluation."""
        self._logic = logic

    def filter_items(self, items: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Filter items based on rules."""
        if not self._rules:
            return items

        results: list[dict[str, Any]] = []
        for item in items:
            if self._logic == "AND":
                if all(rule.matches(item) for rule in self._rules):
                    results.append(item)
            else:
                if any(rule.matches(item) for rule in self._rules):
                    results.append(item)

        return results

    def clear_rules(self) -> None:
        """Clear all rules."""
        self._rules.clear()


def create_default_security_filters() -> AutoFilterEngine:
    """Create default security filter rules."""
    engine = AutoFilterEngine()
    engine.set_logic("AND")  # Fix #340: Use AND so it excludes if ALL exclusions match (wait, the issue said "exclude if ANY matches" for OR, but "AND of negated rules means include if ALL match"? Wait, inverse=True rules return False when they match. If logic is AND, `all(...)` requires all rules to be True to keep the item. If ANY rule is inverse=True and matches, it returns False, so `all(...)` returns False, and the item is excluded. So AND is correct for "exclude if ANY exclusion matches".

    engine.add_rule(
        FilterRule(
            name="Exclude static assets",
            field="url",
            match_type="regex",
            value=r"\.(css|js|png|jpg|gif|svg|ico|woff|woff2)$",
            inverse=True,
        )
    )

    engine.add_rule(
        FilterRule(
            name="Exclude health checks",
            field="url",
            match_type="regex",
            value=r"/(health|healthz|ready|readyz|ping)$",
            inverse=True,
        )
    )

    engine.add_rule(
        FilterRule(
            name="Exclude OPTIONS requests",
            field="method",
            match_type="equals",
            value="OPTIONS",
            inverse=True,
        )
    )

    return engine
