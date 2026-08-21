"""Coverage of finding specs vs families."""

from __future__ import annotations

from src.detection.taxonomy import catalog_taxonomy, families


def coverage_report() -> dict[str, object]:
    taxons = catalog_taxonomy()
    fam = families()
    uncovered = [item.key for item in taxons if item.family == "other"]
    return {
        "total": len(taxons),
        "families": fam,
        "unclassified": uncovered,
        "unclassified_count": len(uncovered),
        "classified_ratio": round((len(taxons) - len(uncovered)) / max(len(taxons), 1), 3),
    }


def assert_minimum_coverage(*, min_ratio: float = 0.4) -> None:
    report = coverage_report()
    ratio = float(report["classified_ratio"])
    if ratio < min_ratio:
        raise AssertionError(f"catalog coverage {ratio} < {min_ratio}")
