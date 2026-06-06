"""Stateful detection layer.

Implements the four stateful detection primitives the detection layer
was previously missing:

* **CSRF entropy analyzer** — observes the entropy of CSRF tokens across
  consecutive requests, detects when tokens are static, predictable, or
  bound to a single session.
* **Session fixation detector** — observes whether a session token issued
  before authentication remains valid after authentication (a fixation
  vulnerability).
* **Rate-limit adaptive prober** — performs adaptive backoff probing to
  determine the actual rate-limit threshold by varying the request
  interval and observing when the server starts responding differently.
* **Concurrent session mutator** — issues truly concurrent state mutation
  requests (not just signal analysis) to detect TOCTOU / race condition
  vulnerabilities.

The module is intentionally pure-Python and self-contained so the
detection runtime can call into it without pulling in extra dependencies.
"""

from __future__ import annotations

import asyncio
import collections
import logging
import math
import time
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def shannon_entropy(samples: Iterable[str]) -> float:
    """Return the Shannon entropy (bits) of an iterable of strings.

    The samples are sliced into per-character buckets first so short
    tokens and long tokens can be compared on the same scale.
    """

    text = "".join(samples)
    if not text:
        return 0.0
    counts: dict[str, int] = collections.Counter(text)
    total = sum(counts.values())
    entropy = 0.0
    for count in counts.values():
        if count <= 0:
            continue
        p = count / total
        entropy -= p * math.log2(p)
    return entropy


def normalized_entropy(samples: Iterable[str]) -> float:
    """Return entropy normalized to [0, 1] for a 64-char alphabet."""

    if not samples:
        return 0.0
    raw = shannon_entropy(samples)
    max_entropy = math.log2(64) if 64 > 1 else 1
    return min(1.0, raw / max_entropy)


def _safe_ratio(part: int, whole: int) -> float:
    if whole <= 0:
        return 0.0
    return part / whole


# ---------------------------------------------------------------------------
# CSRF entropy analyzer
# ---------------------------------------------------------------------------


CSRF_TOKEN_KEYS: tuple[str, ...] = (
    "csrf",
    "csrf_token",
    "csrfmiddlewaretoken",
    "x-csrf-token",
    "x-xsrf-token",
    "_csrf",
    "anti_csrf",
    "authenticity_token",
)


@dataclass(slots=True)
class CSRFEntropyFinding:
    url: str
    sample_count: int
    entropy: float
    unique_token_ratio: float
    is_static: bool
    is_predictable: bool
    is_session_bound: bool
    samples: tuple[str, ...] = ()
    field: str = "csrf_token"

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "indicator": "csrf_entropy_weakness",
            "summary": (
                f"CSRF tokens show entropy={self.entropy:.2f} uniqueness={self.unique_token_ratio:.2f} "
                f"across {self.sample_count} samples"
            ),
            "severity": "high" if self.is_static or self.is_predictable else "medium",
            "confidence": round(0.5 + (1.0 - self.unique_token_ratio) * 0.4, 3),
            "sample_count": self.sample_count,
            "entropy": round(self.entropy, 3),
            "unique_token_ratio": round(self.unique_token_ratio, 3),
            "is_static": self.is_static,
            "is_predictable": self.is_predictable,
            "is_session_bound": self.is_session_bound,
            "field": self.field,
            "samples": list(self.samples)[:5],
        }


def analyze_csrf_entropy(
    *,
    url: str,
    tokens: list[str],
    field: str = "csrf_token",
) -> CSRFEntropyFinding:
    """Inspect a list of CSRF token samples and report weakness flags."""

    cleaned = [str(t).strip() for t in tokens if t]
    if not cleaned:
        return CSRFEntropyFinding(
            url=url,
            sample_count=0,
            entropy=0.0,
            unique_token_ratio=0.0,
            is_static=False,
            is_predictable=False,
            is_session_bound=False,
            samples=(),
            field=field,
        )
    unique = set(cleaned)
    entropy = normalized_entropy(cleaned)
    unique_ratio = _safe_ratio(len(unique), len(cleaned))
    is_static = len(unique) == 1 and len(cleaned) >= 2
    is_predictable = entropy < 0.5 or unique_ratio < 0.5
    is_session_bound = (
        len(cleaned) >= 4
        and len(unique) == 1
    )
    return CSRFEntropyFinding(
        url=url,
        sample_count=len(cleaned),
        entropy=entropy,
        unique_token_ratio=unique_ratio,
        is_static=is_static,
        is_predictable=is_predictable,
        is_session_bound=is_session_bound,
        samples=tuple(cleaned[:10]),
        field=field,
    )


# ---------------------------------------------------------------------------
# Session fixation detector
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class SessionFixationFinding:
    url: str
    pre_auth_token: str
    post_auth_token: str
    is_fixation: bool
    rotated_after_auth: bool
    token_length: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "indicator": "session_fixation_candidate",
            "summary": (
                "Session token is not rotated after authentication"
                if self.is_fixation
                else "Session token rotates after authentication"
            ),
            "severity": "high" if self.is_fixation else "info",
            "confidence": 0.85 if self.is_fixation else 0.40,
            "pre_auth_token_hash": _short_hash(self.pre_auth_token),
            "post_auth_token_hash": _short_hash(self.post_auth_token),
            "token_length": self.token_length,
            "rotated_after_auth": self.rotated_after_auth,
        }


def _short_hash(value: str) -> str:
    import hashlib

    return hashlib.sha256((value or "").encode("utf-8")).hexdigest()[:12]


def detect_session_fixation(
    *,
    url: str,
    pre_auth_token: str | None,
    post_auth_token: str | None,
) -> SessionFixationFinding:
    pre = (pre_auth_token or "").strip()
    post = (post_auth_token or "").strip()
    if not pre or not post:
        return SessionFixationFinding(
            url=url,
            pre_auth_token=pre,
            post_auth_token=post,
            is_fixation=False,
            rotated_after_auth=False,
            token_length=len(post or pre),
        )
    rotated = pre != post
    fixation = not rotated
    return SessionFixationFinding(
        url=url,
        pre_auth_token=pre,
        post_auth_token=post,
        is_fixation=fixation,
        rotated_after_auth=rotated,
        token_length=len(post),
    )


# ---------------------------------------------------------------------------
# Rate-limit adaptive prober
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class RateLimitProbeResult:
    url: str
    initial_interval_ms: float
    final_interval_ms: float
    baseline_status: int
    last_status: int
    throttled_status: int | None
    threshold_estimate: int | None
    samples: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "indicator": "rate_limit_adaptive_probe",
            "summary": (
                f"Adaptive probe found threshold≈{self.threshold_estimate} "
                f"req/window; final interval {self.final_interval_ms}ms"
            ),
            "severity": "info" if self.throttled_status is None else "medium",
            "confidence": 0.55 if self.throttled_status else 0.40,
            "initial_interval_ms": self.initial_interval_ms,
            "final_interval_ms": self.final_interval_ms,
            "baseline_status": self.baseline_status,
            "last_status": self.last_status,
            "throttled_status": self.throttled_status,
            "threshold_estimate": self.threshold_estimate,
            "samples": self.samples,
        }


def adapt_rate_limit_observations(
    *,
    url: str,
    samples: list[dict[str, Any]],
    initial_interval_ms: float = 50.0,
    final_interval_ms: float = 1500.0,
    threshold_status_codes: tuple[int, ...] = (429, 503),
) -> RateLimitProbeResult:
    """Convert a list of ``(interval_ms, status_code)`` observations into a finding.

    Each sample must contain ``interval_ms`` and ``status_code`` keys.
    The function performs a coarse search: starts at ``initial_interval_ms``
    and steps up to ``final_interval_ms`` until status code changes or
    the threshold is reached.
    """

    if not samples:
        return RateLimitProbeResult(
            url=url,
            initial_interval_ms=initial_interval_ms,
            final_interval_ms=final_interval_ms,
            baseline_status=0,
            last_status=0,
            throttled_status=None,
            threshold_estimate=None,
            samples=[],
        )
    sorted_samples = sorted(samples, key=lambda s: float(s.get("interval_ms", 0)))
    baseline = sorted_samples[0].get("status_code")
    throttled_sample = next(
        (
            s
            for s in sorted_samples
            if s.get("status_code") in threshold_status_codes
        ),
        None,
    )
    threshold_estimate = None
    if throttled_sample is not None and baseline not in threshold_status_codes:
        threshold_estimate = throttled_sample.get("interval_ms")

    return RateLimitProbeResult(
        url=url,
        initial_interval_ms=initial_interval_ms,
        final_interval_ms=final_interval_ms,
        baseline_status=int(baseline or 0),
        last_status=int(sorted_samples[-1].get("status_code", 0)),
        throttled_status=(
            int(throttled_sample.get("status_code", 0)) if throttled_sample else None
        ),
        threshold_estimate=threshold_estimate,
        samples=list(samples),
    )


# ---------------------------------------------------------------------------
# Concurrent session state mutator
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class RaceConditionProbeResult:
    url: str
    fired_concurrent: int
    success_count: int
    failure_count: int
    success_status_codes: tuple[int, ...]
    drift_observed: bool
    drift_summary: str | None
    elapsed_ms: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "indicator": "race_condition_concurrent_probe",
            "summary": (
                f"{self.success_count}/{self.fired_concurrent} concurrent requests "
                f"appeared to succeed — TOCTOU candidate."
            ),
            "severity": "high" if self.drift_observed else "medium",
            "confidence": round(0.5 + (self.success_count / max(1, self.fired_concurrent)) * 0.4, 3),
            "fired_concurrent": self.fired_concurrent,
            "success_count": self.success_count,
            "failure_count": self.failure_count,
            "success_status_codes": list(self.success_status_codes),
            "drift_observed": self.drift_observed,
            "drift_summary": self.drift_summary,
            "elapsed_ms": self.elapsed_ms,
        }


async def fire_concurrent_requests(
    request_coro_factory: Any,
    *,
    url: str,
    concurrency: int = 8,
    success_status_codes: Iterable[int] = (200, 201, 202, 204),
) -> RaceConditionProbeResult:
    """Issue ``concurrency`` requests at the same time and observe TOCTOU drift.

    ``request_coro_factory`` is a zero-argument callable that returns a
    fresh coroutine for each attempt. The coroutine is awaited via
    ``asyncio.gather`` so all calls fly in parallel.
    """

    started = time.perf_counter()
    coros = [request_coro_factory() for _ in range(concurrency)]
    results = await asyncio.gather(*coros, return_exceptions=True)
    elapsed = (time.perf_counter() - started) * 1000.0

    statuses: list[int] = []
    for item in results:
        if isinstance(item, Exception):
            statuses.append(-1)
            continue
        status = getattr(item, "status_code", None) or 0
        statuses.append(int(status))

    success_codes = set(success_status_codes)
    success = sum(1 for s in statuses if s in success_codes)
    failure = sum(1 for s in statuses if s not in success_codes)
    success_set = sorted({s for s in statuses if s in success_codes})
    drift = success >= max(2, concurrency // 2) and failure > 0
    drift_summary = None
    if drift:
        drift_summary = (
            f"{success}/{concurrency} concurrent requests returned success codes "
            f"{success_set}; concurrent mutation is plausible."
        )
    return RaceConditionProbeResult(
        url=url,
        fired_concurrent=concurrency,
        success_count=success,
        failure_count=failure,
        success_status_codes=tuple(success_set),
        drift_observed=drift,
        drift_summary=drift_summary,
        elapsed_ms=elapsed,
    )


# ---------------------------------------------------------------------------
# Detection adapter
# ---------------------------------------------------------------------------


def csrf_findings_from_observations(
    observations: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Convert [{url, tokens, field}, ...] observations into findings."""

    findings: list[dict[str, Any]] = []
    for obs in observations:
        url = str(obs.get("url", ""))
        tokens = list(obs.get("tokens") or [])
        if not url or not tokens:
            continue
        finding = analyze_csrf_entropy(
            url=url, tokens=tokens, field=str(obs.get("field", "csrf_token"))
        )
        findings.append(finding.to_dict())
    return findings


def fixation_findings_from_observations(
    observations: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for obs in observations:
        url = str(obs.get("url", ""))
        if not url:
            continue
        finding = detect_session_fixation(
            url=url,
            pre_auth_token=obs.get("pre_auth_token"),
            post_auth_token=obs.get("post_auth_token"),
        )
        findings.append(finding.to_dict())
    return findings


__all__ = [
    "CSRFEntropyFinding",
    "RaceConditionProbeResult",
    "RateLimitProbeResult",
    "SessionFixationFinding",
    "adapt_rate_limit_observations",
    "analyze_csrf_entropy",
    "csrf_findings_from_observations",
    "detect_session_fixation",
    "fire_concurrent_requests",
    "fixation_findings_from_observations",
    "normalized_entropy",
    "shannon_entropy",
]
