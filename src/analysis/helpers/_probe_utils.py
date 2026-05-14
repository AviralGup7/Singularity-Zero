"""Canonical confidence and severity helpers for all active probes."""

__all__ = [
    "probe_confidence",
    "probe_severity",
    "probe_confidence_from_map",
    "probe_severity_from_map",
]


def probe_confidence(
    issues: list[str],
    confidence_map: dict[str, float] | None = None,
    default: float = 0.5,
    cap: float = 0.98,
) -> float:
    """Compute a confidence score from a list of issue identifiers.

    If *confidence_map* is provided it is used as the lookup table;
    otherwise callers should use :func:`probe_confidence_from_map`.
    """
    if confidence_map is not None:
        return probe_confidence_from_map(issues, confidence_map, default, cap)
    return default


def probe_severity(
    issues: list[str],
    severity_map: dict[str, str] | None = None,
    default: str = "low",
) -> str:
    """Return the highest severity from a list of issue identifiers.

    If *severity_map* is provided it is used as the lookup table;
    otherwise callers should use :func:`probe_severity_from_map`.
    """
    if severity_map is not None:
        return probe_severity_from_map(issues, severity_map, default)
    return default


def probe_confidence_from_map(
    issues: list[str],
    confidence_map: dict[str, float],
    default: float = 0.5,
    cap: float = 0.98,
) -> float:
    """Calculate confidence from a custom confidence map."""
    if not issues:
        return default
    max_conf = max(confidence_map.get(issue, default) for issue in issues)
    bonus = min(0.06, len(issues) * 0.02)
    return round(min(max_conf + bonus, cap), 2)


def probe_severity_from_map(
    issues: list[str],
    severity_map: dict[str, str],
    default: str = "low",
) -> str:
    """Determine the highest severity from a list of issues using a severity map."""
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    if not issues:
        return default
    max_sev = min(
        (severity_map.get(issue, default) for issue in issues if issue in severity_map),
        key=lambda s: severity_order.get(s, 3),
        default=default,
    )
    return max_sev
