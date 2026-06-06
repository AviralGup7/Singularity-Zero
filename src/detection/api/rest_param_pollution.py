"""REST parameter pollution (HPP) detector.

HTTP Parameter Pollution is a class of vulnerabilities where an HTTP
endpoint binds the same parameter name multiple times in an unsafe way.
The most common patterns are:

* ``?a=1&a=2`` — repeated query parameter
* ``?a[]=1&a[]=2`` — array-style binding
* JSON ``{"a": 1, "a": 2}`` — duplicate object keys
* Form bodies with the same field name

Different backends interpret these consistently differently:

* PHP historically concatenated values with ``&``
* ASP.NET merged into comma-separated strings
* Node/Express + body-parser exposes an array
* Python/Flask returns the first value (in ``request.values``) and the
  last value (in ``request.args.getlist``) inconsistently

The detector accepts "observations" — captured parameter-binding
behaviour — and decides whether the binding is ambiguous, unsafe, or
exploitable. The handlers in :mod:`src.detection.handlers` collect
observations by replaying the target with HPP payloads and reporting
the response shape (status, body length, repeated value count).
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qsl, urlsplit

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class RestParamPollutionFinding:
    """A single REST parameter pollution candidate."""

    url: str
    parameter: str
    binding_style: str
    observed_values: tuple[str, ...]
    status_code: int | None
    is_ambiguous: bool
    is_array_binding: bool
    is_concat_binding: bool
    severity: str
    confidence: float
    summary: str
    remediation_hint: str | None = None
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "indicator": "rest_parameter_pollution",
            "summary": self.summary,
            "severity": self.severity,
            "confidence": round(self.confidence, 3),
            "parameter": self.parameter,
            "binding_style": self.binding_style,
            "observed_values": list(self.observed_values),
            "is_ambiguous": self.is_ambiguous,
            "is_array_binding": self.is_array_binding,
            "is_concat_binding": self.is_concat_binding,
            "status_code": self.status_code,
            "remediation_hint": self.remediation_hint,
            "evidence": self.evidence,
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _detect_array_binding(values: Iterable[str]) -> bool:
    """Return True if the parameter was bound as an array of distinct tokens."""

    items = [str(v) for v in values if v is not None]
    if len(items) < 2:
        return False
    if any("," in v for v in items):
        return False
    return len(set(items)) == len(items)


def _detect_concat_binding(values: Iterable[str]) -> bool:
    """Return True if the framework merged the values into a single string.

    A response is classified as concat-bound when one of the observed
    values is composed of the others separated by a delimiter (e.g. the
    PHP/ASP classic ``?a=1&a=2`` → server returns ``"1,2"``).
    """

    items = [str(v) for v in values if v is not None]
    if len(items) < 2:
        return False
    items_set = set(items)
    delimiters = (",", "&", ";", "|", " ", "\t")
    for candidate in items:
        if not any(delim in candidate for delim in delimiters):
            continue
        for delim in delimiters:
            if delim not in candidate:
                continue
            parts = [part for part in candidate.split(delim) if part]
            if not parts or len(parts) < 2:
                continue
            if all(part in items_set for part in parts):
                return True
    return False


def _binding_style(values: Iterable[str]) -> str:
    items = [str(v) for v in values if v is not None]
    if not items:
        return "unknown"
    if _detect_array_binding(items):
        return "array"
    if _detect_concat_binding(items):
        return "concat"
    if len(set(items)) == 1 and len(items) > 1:
        return "last_wins"
    return "first_wins"


def _is_polluted(
    *,
    binding: str,
    status: int | None,
    requested: int,
    distinct: int,
) -> bool:
    """A parameter is "polluted" when the binding introduces ambiguity.

    Heuristics:
      * array / concat binding with more than one value → polluted
      * repeated identical values bind to the same value but may still
        indicate the framework silently dropped one (e.g. PHP-style
        concat, Rails last-wins)
    """

    if requested < 2:
        return False
    if binding in {"array", "concat"}:
        return True
    if status is not None and status >= 500:
        return True
    if distinct > 1 and binding in {"first_wins", "last_wins"}:
        return True
    return False


# ---------------------------------------------------------------------------
# Core analysis
# ---------------------------------------------------------------------------


def analyze_rest_parameter_pollution(
    *,
    url: str,
    parameter: str,
    observed_values: Iterable[str],
    status_code: int | None = None,
    extra: dict[str, Any] | None = None,
) -> RestParamPollutionFinding:
    """Classify a single parameter observation.

    Args:
        url: The URL that was probed.
        parameter: The parameter name that was repeated.
        observed_values: The list of values that the server appeared to bind.
        status_code: HTTP status observed for the probe.
        extra: Optional dict merged into the finding's ``evidence`` block.

    Returns:
        A :class:`RestParamPollutionFinding` describing the binding style,
        ambiguity, and severity.
    """

    values = tuple(str(v) for v in observed_values if v is not None)
    binding = _binding_style(values)
    distinct = len(set(values))
    polluted = _is_polluted(
        binding=binding,
        status=status_code,
        requested=len(values),
        distinct=distinct,
    )
    is_array = binding == "array"
    is_concat = binding == "concat"

    if polluted and is_array:
        severity = "high"
        confidence = 0.75
        summary = (
            f"Parameter '{parameter}' binds multiple values as an array "
            f"({len(values)} values, {distinct} distinct). Server-side "
            "filtering on a single value is bypassable."
        )
    elif polluted and is_concat:
        severity = "high"
        confidence = 0.70
        summary = (
            f"Parameter '{parameter}' concatenates repeated values "
            f"({','.join(values)[:80]!r}) — classic PHP/ASP-style HPP."
        )
    elif polluted and status_code is not None and status_code >= 500:
        severity = "medium"
        confidence = 0.55
        summary = (
            f"Parameter '{parameter}' caused a {status_code} response when "
            f"repeated {len(values)} times — server-side binding crash."
        )
    elif polluted:
        severity = "medium"
        confidence = 0.50
        summary = (
            f"Parameter '{parameter}' silently dropped one of the "
            f"{len(values)} repeated values — inconsistent binding."
        )
    else:
        severity = "info"
        confidence = 0.30
        summary = (
            f"Parameter '{parameter}' consistently bound to "
            f"{len(values)} value(s); no pollution observed."
        )

    return RestParamPollutionFinding(
        url=url,
        parameter=parameter,
        binding_style=binding,
        observed_values=values,
        status_code=status_code,
        is_ambiguous=polluted,
        is_array_binding=is_array,
        is_concat_binding=is_concat,
        severity=severity,
        confidence=confidence,
        summary=summary,
        remediation_hint=(
            "Reject duplicate parameter names at the gateway/edge and "
            "consistently bind to a single value (RFC 3986 last-wins)."
            if polluted
            else None
        ),
        evidence=dict(extra or {}),
    )


# ---------------------------------------------------------------------------
# Observation adapter
# ---------------------------------------------------------------------------


def rest_param_pollution_findings_from_observations(
    observations: Iterable[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Convert [{url, parameter, observed_values, status_code}, ...] to findings.

    The handler in :mod:`src.detection.handlers` builds these observations
    by replaying each priority URL with HPP payloads and capturing the
    response. The observation dict may also contain ``extra`` to surface
    additional evidence (body snippet, query string, etc.).
    """

    findings: list[dict[str, Any]] = []
    for obs in observations:
        url = str(obs.get("url", "")).strip()
        parameter = str(obs.get("parameter", "")).strip()
        if not url or not parameter:
            continue
        observed = obs.get("observed_values") or obs.get("values") or []
        if isinstance(observed, str):
            observed = [observed]
        finding = analyze_rest_parameter_pollution(
            url=url,
            parameter=parameter,
            observed_values=list(observed),
            status_code=obs.get("status_code"),
            extra=obs.get("extra"),
        )
        findings.append(finding.to_dict())
    return findings


# ---------------------------------------------------------------------------
# URL-side helpers (used by the handler when capturing repeated query keys)
# ---------------------------------------------------------------------------


def repeated_query_parameters(url: str) -> dict[str, list[str]]:
    """Return a mapping of query parameters that appear more than once."""

    parsed = urlsplit(url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    grouped: dict[str, list[str]] = {}
    for key, value in pairs:
        grouped.setdefault(key, []).append(value)
    return {key: values for key, values in grouped.items() if len(values) > 1}


__all__ = [
    "RestParamPollutionFinding",
    "analyze_rest_parameter_pollution",
    "repeated_query_parameters",
    "rest_param_pollution_findings_from_observations",
]
