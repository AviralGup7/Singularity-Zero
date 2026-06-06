"""API rate-limiting differential detector.

Different endpoints in the same application often have very different
rate-limit profiles:

* Public ``/login`` is usually throttled at 5 req/min/IP.
* ``/api/graphql`` may bypass rate limits because it sits behind a CDN.
* ``/api/orders/checkout`` may have a generous limit but no
  per-user limit.
* Static ``/api/v1/manifest.json`` may not be throttled at all (and
  that's fine, but it is useful intel).

The detector ingests ``RateLimitEndpointObservation`` rows — captured
``429``/``503`` responses and ``RateLimit-*`` / ``X-RateLimit-*`` /
``Retry-After`` headers — and computes:

* The effective rate-limit threshold per endpoint.
* A per-endpoint profile with method, status, observed limits.
* A diff between endpoints: which endpoint is the weakest link, which
  endpoints are missing limits entirely, and which are inconsistent
  with the rest of the application.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class RateLimitEndpointObservation:
    """A single rate-limit observation against a specific endpoint.

    Attributes:
        url: The URL the probe was sent to.
        method: HTTP method used.
        status_code: Observed status code (200, 429, 503, etc.).
        rate_limit_remaining: The ``X-RateLimit-Remaining`` value if present.
        rate_limit_limit: The ``X-RateLimit-Limit`` value if present.
        rate_limit_reset: The ``X-RateLimit-Reset`` value if present.
        retry_after: The ``Retry-After`` value if present.
        throttled: Whether the response was a 429/503 throttling response.
        request_count: Number of requests fired to trigger the observation.
    """

    url: str
    method: str = "GET"
    status_code: int | None = None
    rate_limit_remaining: int | None = None
    rate_limit_limit: int | None = None
    rate_limit_reset: int | None = None
    retry_after: float | None = None
    throttled: bool = False
    request_count: int | None = None

    def endpoint_key(self) -> str:
        parsed = urlsplit(self.url)
        return f"{parsed.netloc.lower()}{parsed.path or '/'}"


@dataclass(slots=True)
class RateLimitEndpointProfile:
    """A per-endpoint aggregate profile built from observations."""

    url: str
    endpoint_key: str
    method: str
    sample_count: int
    observed_limits: tuple[int, ...]
    observed_remaining: tuple[int, ...]
    throttle_count: int
    has_rate_limit_headers: bool
    has_retry_after: bool
    method_inventory: tuple[str, ...] = ()
    missing_limit: bool = False
    notes: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return {
            "endpoint_key": self.endpoint_key,
            "url": self.url,
            "method": self.method,
            "sample_count": self.sample_count,
            "observed_limits": list(self.observed_limits),
            "observed_remaining": list(self.observed_remaining),
            "throttle_count": self.throttle_count,
            "has_rate_limit_headers": self.has_rate_limit_headers,
            "has_retry_after": self.has_retry_after,
            "method_inventory": list(self.method_inventory),
            "missing_limit": self.missing_limit,
            "notes": list(self.notes),
        }


# ---------------------------------------------------------------------------
# Core analysis
# ---------------------------------------------------------------------------


def _coerce_int(value: object) -> int | None:
    if value is None:
        return None
    try:
        ivalue = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    return ivalue if ivalue >= 0 else None


def _coerce_float(value: object) -> float | None:
    if value is None:
        return None
    try:
        fvalue = float(str(value).strip())
    except (TypeError, ValueError):
        return None
    return fvalue if fvalue >= 0 else None


def _is_throttle_status(status: int | None) -> bool:
    return status in (429, 503, 509)


def _cost_class(url: str) -> str:
    """Heuristic to identify endpoints that should always be throttled."""

    lowered = url.lower()
    sensitive_tokens = (
        "login",
        "signin",
        "auth",
        "token",
        "password",
        "reset",
        "register",
        "signup",
        "checkout",
        "payment",
        "redeem",
        "coupon",
        "transfer",
        "withdraw",
        "forgot",
        "2fa",
        "verify",
        "otp",
        "graphql",
    )
    if any(token in lowered for token in sensitive_tokens):
        return "sensitive"
    return "generic"


def build_endpoint_profiles(
    observations: Iterable[RateLimitEndpointObservation | dict[str, Any]],
) -> dict[str, RateLimitEndpointProfile]:
    """Aggregate per-endpoint observations into profiles."""

    buckets: dict[tuple[str, str], list[RateLimitEndpointObservation]] = {}
    latest_url: dict[tuple[str, str], str] = {}
    for obs in observations:
        if isinstance(obs, dict):
            obs = RateLimitEndpointObservation(
                url=str(obs.get("url", "")).strip(),
                method=str(obs.get("method", "GET")).upper(),
                status_code=obs.get("status_code"),
                rate_limit_remaining=_coerce_int(obs.get("rate_limit_remaining")),
                rate_limit_limit=_coerce_int(obs.get("rate_limit_limit")),
                rate_limit_reset=_coerce_int(obs.get("rate_limit_reset")),
                retry_after=_coerce_float(obs.get("retry_after")),
                throttled=bool(obs.get("throttled", _is_throttle_status(obs.get("status_code")))),
                request_count=_coerce_int(obs.get("request_count")),
            )
        if not obs.url:
            continue
        key = (obs.endpoint_key(), obs.method.upper())
        buckets.setdefault(key, []).append(obs)
        latest_url[key] = obs.url

    profiles: dict[str, RateLimitEndpointProfile] = {}
    for (endpoint_key, method), rows in buckets.items():
        limits = tuple(
            sorted(
                {
                    int(obs.rate_limit_limit)
                    for obs in rows
                    if obs.rate_limit_limit is not None
                }
            )
        )
        remaining = tuple(
            int(obs.rate_limit_remaining)
            for obs in rows
            if obs.rate_limit_remaining is not None
        )
        throttle_count = sum(1 for obs in rows if obs.throttled or _is_throttle_status(obs.status_code))
        has_headers = any(obs.rate_limit_limit is not None for obs in rows) or any(
            obs.rate_limit_remaining is not None for obs in rows
        )
        has_retry_after = any(obs.retry_after is not None for obs in rows)
        missing = not has_headers and not has_retry_after
        methods_seen = tuple(sorted({obs.method.upper() for obs in rows}))
        notes: list[str] = []
        if throttle_count and not has_headers:
            notes.append("throttled_without_headers")
        if len(limits) > 1:
            notes.append("inconsistent_limit_header")
        if missing:
            notes.append("missing_rate_limit_signals")

        profile = RateLimitEndpointProfile(
            url=latest_url[(endpoint_key, method)],
            endpoint_key=endpoint_key,
            method=method,
            sample_count=len(rows),
            observed_limits=limits,
            observed_remaining=remaining,
            throttle_count=throttle_count,
            has_rate_limit_headers=has_headers,
            has_retry_after=has_retry_after,
            method_inventory=methods_seen,
            missing_limit=missing,
            notes=tuple(notes),
        )
        profiles[endpoint_key] = profile
    return profiles


def endpoint_profiles_to_findings(
    profiles: dict[str, RateLimitEndpointProfile],
) -> list[dict[str, Any]]:
    """Convert a profile map into a list of detection findings.

    The diff logic compares every profile against the median observed
    limit and reports:

    * **sensitive_missing_limit** — sensitive endpoint with no observed
      rate-limit headers or throttling (the most important finding).
    * **weakest_link** — endpoint whose observed limit is the lowest in
      the application; useful for prioritization.
    * **inconsistent_limit** — endpoint that returns different limit
      headers across samples.
    * **missing_limit_generic** — generic endpoint with no limit signal
      (informational).
    """

    findings: list[dict[str, Any]] = []
    if not profiles:
        return findings

    limits_present = [
        profile.observed_limits[0]
        for profile in profiles.values()
        if profile.observed_limits
    ]
    median_limit = _median(limits_present) if limits_present else 0
    weakest_limit = min(limits_present) if limits_present else None

    for profile in profiles.values():
        cost = _cost_class(profile.url)
        lowest = min(profile.observed_limits) if profile.observed_limits else None
        is_weakest = (
            weakest_limit is not None
            and lowest is not None
            and lowest == weakest_limit
            and len(limits_present) > 1
        )

        if cost == "sensitive" and profile.missing_limit:
            severity = "high"
            confidence = 0.85
            indicator = "api_rate_limit_missing_sensitive"
            summary = (
                f"Sensitive endpoint {profile.endpoint_key} returned no "
                "rate-limit headers and was never throttled — open to "
                "credential stuffing / brute force."
            )
            recommendation = (
                "Add a per-IP and per-account rate limit to authentication "
                "endpoints; emit 429 with Retry-After on overflow."
            )
        elif is_weakest and cost == "sensitive":
            severity = "high"
            confidence = 0.75
            indicator = "api_rate_limit_weakest_link_sensitive"
            summary = (
                f"Sensitive endpoint {profile.endpoint_key} throttles at "
                f"{lowest} req/window while the rest of the app enforces "
                f"~{median_limit} req/window — weakest link."
            )
            recommendation = "Align the rate limit on sensitive endpoints with the rest of the API."
        elif is_weakest:
            severity = "medium"
            confidence = 0.65
            indicator = "api_rate_limit_weakest_link"
            summary = (
                f"Endpoint {profile.endpoint_key} throttles at {lowest} "
                f"req/window, lower than the application median of "
                f"~{median_limit} req/window."
            )
            recommendation = None
        elif "inconsistent_limit_header" in profile.notes:
            severity = "medium"
            confidence = 0.55
            indicator = "api_rate_limit_header_inconsistent"
            summary = (
                f"Endpoint {profile.endpoint_key} returns inconsistent "
                f"limit headers across samples {profile.observed_limits}."
            )
            recommendation = (
                "Make rate-limit header values consistent (or use a "
                "structured header like RateLimit-Reset / RateLimit-Policy)."
            )
        elif profile.missing_limit and cost == "generic":
            severity = "low"
            confidence = 0.45
            indicator = "api_rate_limit_missing_generic"
            summary = (
                f"Endpoint {profile.endpoint_key} has no observed rate-limit "
                "headers. Add a default limit unless the endpoint is purely "
                "static."
            )
            recommendation = None
        else:
            severity = "info"
            confidence = 0.40
            indicator = "api_rate_limit_baseline"
            summary = (
                f"Endpoint {profile.endpoint_key} enforces ~{lowest or median_limit} "
                f"req/window across {profile.sample_count} samples."
            )
            recommendation = None

        finding: dict[str, Any] = {
            "url": profile.url,
            "indicator": indicator,
            "summary": summary,
            "severity": severity,
            "confidence": round(confidence, 3),
            "endpoint_key": profile.endpoint_key,
            "endpoint_cost_class": cost,
            "sample_count": profile.sample_count,
            "observed_limits": list(profile.observed_limits),
            "observed_remaining": list(profile.observed_remaining),
            "throttle_count": profile.throttle_count,
            "has_rate_limit_headers": profile.has_rate_limit_headers,
            "has_retry_after": profile.has_retry_after,
            "missing_limit": profile.missing_limit,
            "weakest_link": is_weakest,
            "notes": list(profile.notes),
        }
        if recommendation:
            finding["remediation_hint"] = recommendation
        findings.append(finding)

    findings.sort(key=lambda item: (-_severity_score(item["severity"]), item["endpoint_key"]))
    return findings


def _median(values: list[int]) -> int:
    if not values:
        return 0
    sorted_values = sorted(values)
    mid = len(sorted_values) // 2
    if len(sorted_values) % 2:
        return int(sorted_values[mid])
    return int((sorted_values[mid - 1] + sorted_values[mid]) / 2)


def _severity_score(severity: str) -> int:
    order = {
        "critical": 4,
        "high": 3,
        "medium": 2,
        "low": 1,
        "info": 0,
    }
    return order.get(severity.lower(), 0)


__all__ = [
    "RateLimitEndpointObservation",
    "RateLimitEndpointProfile",
    "build_endpoint_profiles",
    "endpoint_profiles_to_findings",
]
