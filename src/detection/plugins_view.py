"""Flatten detection plugins into a UI-friendly table."""

from __future__ import annotations

from typing import Any

from src.detection.taxonomy import classify_key


def rows_from_options(options: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for option in options:
        key = str(option.get("name") or option.get("key") or "")
        taxon = classify_key(key)
        rows.append(
            {
                "key": key,
                "label": option.get("label") or key,
                "group": option.get("group") or taxon.family,
                "family": taxon.family,
                "surface": taxon.surface,
                "tier": option.get("detection_tier") or "passive",
                "enabled": bool(option.get("enabled_by_default", True)),
                "confidence": float(option.get("baseline_confidence") or 0.5),
            }
        )
    return sorted(rows, key=lambda item: (item["family"], item["key"]))


def enabled_keys(rows: list[dict[str, Any]]) -> list[str]:
    return [row["key"] for row in rows if row.get("enabled")]
