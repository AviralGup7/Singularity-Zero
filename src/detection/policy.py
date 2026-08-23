"""Which detectors to run for a given scan mode."""

from __future__ import annotations

from src.detection.taxonomy import catalog_taxonomy, classify_key

MODE_FAMILIES: dict[str, frozenset[str]] = {
    "idor": frozenset({"access"}),
    "ssrf": frozenset({"ssrf"}),
    "xss": frozenset({"injection"}),
    "sqli": frozenset({"injection"}),
    "api": frozenset({"api", "access"}),
    "standard": frozenset({"injection", "access", "misconfig", "api", "ssrf"}),
    "full": frozenset(),
}


def keys_for_mode(mode: str) -> list[str]:
    families = MODE_FAMILIES.get(str(mode or "standard").lower())
    taxons = catalog_taxonomy()
    if not families:
        return [item.key for item in taxons]
    return [item.key for item in taxons if item.family in families]


def should_run(key: str, mode: str) -> bool:
    families = MODE_FAMILIES.get(str(mode or "standard").lower())
    if not families:
        return True
    return classify_key(key).family in families
