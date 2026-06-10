"""Web cache poisoning validator (R7).

Detects when unkeyed request inputs (e.g. ``X-Forwarded-Host``,
``X-Original-URL``) leak into the response and are subsequently cached.

The validator expects an active ``probe_cache`` callable that takes a target
URL and an ``unkeyed_header`` mapping, and returns a dict describing both
the unkeyed probe response and a "normal" follow-up response. Cache
poisoning is confirmed when:
1. The unkeyed value is reflected in the probe response, AND
2. The follow-up response (without the unkeyed header) still includes the
   poisoned value, AND
3. The response advertises caching via ``X-Cache``/``Age``/``Vary`` or
   similar headers.

The validator is best-effort and offline-friendly: callers can supply a
custom ``probe_cache`` implementation.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

from src.execution.validators.config.scoring_config import ScoringConfig
from src.execution.validators.status import ValidationStatus
from src.execution.validators.validators.shared import (
    bounded_confidence,
    to_validation_result,
)

logger = logging.getLogger(__name__)

CACHE_INDICATOR_HEADERS = (
    "x-cache",
    "x-cache-status",
    "cf-cache-status",
    "age",
    "x-served-by",
    "x-amz-cf-pop",
    "x-vercel-cache",
    "fastly-debug-digest",
    "via",
)


def _is_cache_hit(headers: dict[str, str]) -> bool:
    lowered = {str(k).lower(): str(v).lower() for k, v in (headers or {}).items()}
    for header in CACHE_INDICATOR_HEADERS:
        if header in lowered:
            value = lowered[header]
            if header == "age":
                try:
                    if int(value.split(";")[0].strip()) > 0:
                        return True
                except (TypeError, ValueError):
                    continue
            elif header == "x-amz-cf-pop":
                return True
            elif any(token in value for token in ("hit", "stale", "revalidated", "dynamic")):
                return True
    return False


def evaluate_cache_poison(
    *,
    target_url: str,
    unkeyed_header: str,
    probe_response: dict[str, Any] | None,
    followup_response: dict[str, Any] | None,
    scoring: ScoringConfig,
    in_scope: bool = True,
) -> dict[str, Any]:
    """Evaluate a cache poisoning probe.

    Args:
        target_url: The URL tested.
        unkeyed_header: Name of the unkeyed header used in the probe.
        probe_response: Dict returned by the first request (with unkeyed
            header set to a unique poison value). Expected keys:
            ``status_code``, ``headers``, ``body``.
        followup_response: Dict returned by the second "normal" request.
        scoring: Per-validator ``ScoringConfig``.
        in_scope: Whether the target endpoint is in scope.

    Returns:
        Dict with status/confidence/signals/evidence/bonuses.
    """
    signals: list[str] = []
    bonuses: list[float] = []
    notes: list[str] = []

    if not probe_response or not followup_response:
        return {
            "status": ValidationStatus.INCONCLUSIVE.value,
            "confidence": 0.0,
            "signals": [],
            "evidence": {"reason": "missing_probe_or_followup"},
            "bonuses": [],
        }

    probe_body = str(probe_response.get("body", "") or "")
    followup_body = str(followup_response.get("body", "") or "")
    probe_headers = probe_response.get("headers") or {}
    followup_headers = followup_response.get("headers") or {}

    probe_status = int(probe_response.get("status_code", 0) or 0)
    followup_status = int(followup_response.get("status_code", 0) or 0)

    probe_cache_hit = _is_cache_hit(probe_headers)
    followup_cache_hit = _is_cache_hit(followup_headers)

    # Extract the unique poison token from the probe response. Callers are
    # expected to inject a token like ``cacheprobe-<uuid>`` into the
    # unkeyed header value.
    token = str(probe_response.get("probe_token", "")).strip()
    if not token:
        return {
            "status": ValidationStatus.INCONCLUSIVE.value,
            "confidence": 0.0,
            "signals": [],
            "evidence": {"reason": "missing_probe_token"},
            "bonuses": [],
        }

    in_probe = token in probe_body
    in_followup = token in followup_body
    in_probe_headers = any(token in str(value) for value in probe_headers.values())
    in_followup_headers = any(token in str(value) for value in followup_headers.values())

    if in_probe or in_probe_headers:
        signals.append("unkeyed_reflected_in_response")
        bonuses.append(0.08)
        notes.append(f"Unkeyed header {unkeyed_header} reflected in probe response.")

    if (in_followup or in_followup_headers) and (in_probe or in_probe_headers):
        signals.append("cached_unkeyed_input")
        bonuses.append(0.22)
        notes.append("Unkeyed input persisted into a subsequent response (cache poison).")

    if followup_cache_hit and (in_probe or in_probe_headers):
        signals.append("x_cache_hit_with_payload")
        bonuses.append(0.12)
        notes.append("Subsequent response was a cache hit while carrying the poison payload.")

    if probe_status != followup_status and (in_probe or in_probe_headers):
        signals.append("status_difference_with_unkeyed_input")
        bonuses.append(0.04)
        notes.append("Status code changed between probe and follow-up requests.")

    # --- POET (Parameter-Order-based Exploitation Technique) ---
    # Test whether query parameter order affects caching. Send a request
    # with parameters in reversed order and check if the response changes.
    # This is a passive check - callers should supply reversed_params
    # probe data via context.
    reversed_params = probe_response.get("reversed_params_response")
    if reversed_params:
        rp_status = int(reversed_params.get("status_code", 0) or 0)
        if rp_status != probe_status:
            signals.append("poet_parameter_order_caching")
            bonuses.append(0.10)
            notes.append("Parameter order affects cache key (POET vulnerability)")

    # --- Fat GET smuggling ---
    # Send a GET request with a body (fat GET). If the server processes
    # both the body and caches the response, the next GET without a body
    # may receive the poisoned content.
    fat_get_response = probe_response.get("fat_get_response")
    if fat_get_response:
        fg_status = int(fat_get_response.get("status_code", 0) or 0)
        fg_cache_hit = _is_cache_hit(fat_get_response.get("headers", {}))
        if fg_status == 200 and fg_cache_hit:
            signals.append("fat_get_cached")
            bonuses.append(0.14)
            notes.append("GET request with body was cached (fat GET smuggling)")

    # --- CRLF header injection into cache key ---
    # Check if CRLF sequences in header values affect the cache key.
    crlf_response = probe_response.get("crlf_response")
    if crlf_response:
        crlf_body = str(crlf_response.get("body", "") or "")
        crlf_status = int(crlf_response.get("status_code", 0) or 0)
        if crlf_status == 200 and token in crlf_body:
            signals.append("crlf_header_injection_cached")
            bonuses.append(0.12)
            notes.append("CRLF injection in header affected cache key")

    if signals and in_scope and "cached_unkeyed_input" in signals:
        status = ValidationStatus.CONFIRMED.value
    elif signals and in_scope:
        status = ValidationStatus.HEURISTIC.value
    elif signals:
        status = ValidationStatus.HEURISTIC.value
    else:
        status = ValidationStatus.INCONCLUSIVE.value

    confidence = bounded_confidence(
        base=scoring.base,
        cap=scoring.cap,
        bonuses=bonuses,
    )
    evidence = {
        "unkeyed_header": unkeyed_header,
        "probe_token": token,
        "probe_status_code": probe_status,
        "followup_status_code": followup_status,
        "probe_cache_hit": probe_cache_hit,
        "followup_cache_hit": followup_cache_hit,
        "signals": signals,
        "notes": notes,
        "probe_response_headers": dict(probe_headers),
        "followup_response_headers": dict(followup_headers),
    }
    return {
        "status": status,
        "confidence": confidence,
        "signals": signals,
        "evidence": evidence,
        "bonuses": bonuses,
    }


def validate_cache_poison(
    *,
    target_url: str,
    unkeyed_header: str,
    probe_response: dict[str, Any],
    followup_response: dict[str, Any],
    scoring: ScoringConfig,
    in_scope: bool = True,
) -> dict[str, Any]:
    """Validate a cache poisoning probe and return a result dict."""
    evaluation = evaluate_cache_poison(
        target_url=target_url,
        unkeyed_header=unkeyed_header,
        probe_response=probe_response,
        followup_response=followup_response,
        scoring=scoring,
        in_scope=in_scope,
    )
    item = {
        "url": target_url,
        "status": evaluation["status"],
        "confidence": evaluation["confidence"],
        "in_scope": in_scope,
        "scope_reason": "scope_evaluated" if in_scope else "scope_unavailable_or_out_of_scope",
        "evidence": evaluation["evidence"],
    }
    return to_validation_result(
        item, validator="cache_poisoning", category="cache_poisoning"
    ).__dict__


def validate(target: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
    """R1 facade entry point matching the ``Validator`` Protocol.

    Without explicit ``probe_response``/``followup_response`` in
    ``context`` this returns an inconclusive passive result; the engine
    class ``CachePoisoningValidator`` performs the active probe.
    """
    from src.execution.validators.config.scoring_config import (
        DEFAULT_SCORING_CONFIG,
    )

    target_url = str(target.get("url", ""))
    probe_response = context.get("probe_response")
    followup_response = context.get("followup_response")
    unkeyed_header = str(context.get("unkeyed_header", "X-Forwarded-Host"))
    if not (isinstance(probe_response, dict) and isinstance(followup_response, dict)):
        return to_validation_result(
            {
                "url": target_url,
                "status": ValidationStatus.INCONCLUSIVE.value,
                "confidence": 0.0,
                "in_scope": bool(context.get("in_scope", True)),
                "scope_reason": "no_probe_data",
            },
            validator="cache_poisoning",
            category="cache_poisoning",
        ).__dict__
    return validate_cache_poison(
        target_url=target_url,
        unkeyed_header=unkeyed_header,
        probe_response=probe_response,
        followup_response=followup_response,
        scoring=DEFAULT_SCORING_CONFIG["cache_poisoning"],
        in_scope=bool(context.get("in_scope", True)),
    )


def default_probe_cache(
    *,
    request_fn: Callable[..., Any] | None = None,
) -> Callable[..., dict[str, Any]]:
    """Return a probe callable that uses ``request_fn`` for HTTP.

    If ``request_fn`` is None, returns a callable that always reports
    ``missing_probe_or_followup`` and lets the caller iterate.
    """

    def _probe(
        target_url: str,
        unkeyed_header: str,
        poison_value: str,
        **_kwargs: Any,
    ) -> dict[str, Any]:
        if request_fn is None:
            return {
                "status_code": 0,
                "headers": {},
                "body": "",
                "probe_token": poison_value,
            }
        probe = request_fn(
            target_url,
            extra_headers={unkeyed_header: poison_value},
        )
        followup = request_fn(target_url)
        return {
            "probe_response": {
                "status_code": probe.get("status_code", 0),
                "headers": probe.get("headers", {}),
                "body": probe.get("body", ""),
                "probe_token": poison_value,
            },
            "followup_response": {
                "status_code": followup.get("status_code", 0),
                "headers": followup.get("headers", {}),
                "body": followup.get("body", ""),
            },
        }

    return _probe
