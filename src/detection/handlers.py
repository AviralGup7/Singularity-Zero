"""Pluggable detection handlers for the new runtime layer.

These handlers are bound into the plugin runtime under the standard
ANALYZER_BINDING kind so the rest of the pipeline can schedule them
like every other analyzer. They are deliberately thin adapters around
the new modules:

* :mod:`src.detection.ast` — JS sink/source, WASM, prototype pollution.
* :mod:`src.detection.browser` — headless DOM runtime detection.
* :mod:`src.detection.waf` — WAF fingerprinting + bypass strategies.
* :mod:`src.detection.stateful` — CSRF entropy, session fixation,
  rate-limit adaptive probing, concurrent race probing.
* :mod:`src.detection.api` — API-specific detection: REST parameter
  pollution, GraphQL introspection presence, API rate-limit
  differentials, JWT claim manipulation, and WebSocket message-level
  security.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# JS sink/source analyzer
# ---------------------------------------------------------------------------


def js_sink_source_analyzer(
    responses: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Adapter that runs the AST analyzer across HTML responses."""

    from src.detection.ast import analyze_response

    findings: list[dict[str, Any]] = []
    for response in responses:
        url = str(response.get("url", "")).strip()
        if not url:
            continue
        body = response.get("body_text") or response.get("body") or ""
        content_type = response.get("content_type", "")
        for finding in analyze_response(
            url=url, body=body, content_type=content_type
        ):
            finding.setdefault("analyzer_key", "js_sink_source_analyzer")
            finding.setdefault("phase", "analyze")
            findings.append(finding)
    return findings


# ---------------------------------------------------------------------------
# WASM module introspector
# ---------------------------------------------------------------------------


def wasm_module_introspector(
    responses: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Adapter that runs the Wasm introspector on every binary response."""

    from src.detection.ast import analyze_wasm_candidates

    candidates: list[tuple[str, bytes | None]] = []
    url_by_key: dict[str, str] = {}
    for response in responses:
        url = str(response.get("url", "")).strip()
        if not url:
            continue
        body = response.get("body")
        if isinstance(body, (bytes, bytearray)) and body:
            candidates.append((url, bytes(body)))
            url_by_key[url] = url
        else:
            candidates.append((url, None))
    findings: list[dict[str, Any]] = []
    for finding in analyze_wasm_candidates(candidates):
        finding.setdefault("analyzer_key", "wasm_module_introspector")
        finding.setdefault("phase", "analyze")
        findings.append(finding)
    return findings


# ---------------------------------------------------------------------------
# Prototype pollution walker
# ---------------------------------------------------------------------------


def prototype_pollution_walker(
    responses: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Adapter that runs the prototype pollution walker on HTML and JSON responses."""

    from src.detection.ast import (
        analyze_html_for_prototype_pollution,
        analyze_object_for_prototype_pollution,
    )

    findings: list[dict[str, Any]] = []
    for response in responses:
        url = str(response.get("url", "")).strip()
        if not url:
            continue
        body = response.get("body_text") or response.get("body") or ""
        if not body:
            continue
        content_type = str(response.get("content_type", "")).lower()
        if "html" in content_type or "<html" in str(body).lower() or "<script" in str(body).lower():
            for finding in analyze_html_for_prototype_pollution(str(body), url=url):
                finding.setdefault("analyzer_key", "prototype_pollution_walker")
                finding.setdefault("phase", "analyze")
                findings.append(finding)
        elif "json" in content_type or str(body).lstrip().startswith(("{", "[")):
            for finding in analyze_object_for_prototype_pollution(str(body), url=url):
                finding.setdefault("analyzer_key", "prototype_pollution_walker")
                finding.setdefault("phase", "analyze")
                findings.append(finding)
    return findings


# ---------------------------------------------------------------------------
# DOM runtime detector
# ---------------------------------------------------------------------------


def dom_runtime_analyzer(
    responses: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Adapter that runs the headless/static DOM detector."""

    from src.detection.browser import findings_from_response

    findings: list[dict[str, Any]] = []
    for response in responses:
        url = str(response.get("url", "")).strip()
        if not url:
            continue
        body = response.get("body_text") or response.get("body") or ""
        content_type = response.get("content_type", "")
        for finding in findings_from_response(
            url=url, body_text=str(body) if body else None, content_type=str(content_type)
        ):
            finding.setdefault("analyzer_key", "dom_runtime_analyzer")
            finding.setdefault("phase", "analyze")
            findings.append(finding)
    return findings


# ---------------------------------------------------------------------------
# WAF fingerprint + challenge
# ---------------------------------------------------------------------------


def waf_fingerprint_analyzer(
    responses: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    from src.detection.waf import fingerprint_response, fingerprint_to_finding

    findings: list[dict[str, Any]] = []
    for response in responses:
        url = str(response.get("url", "")).strip()
        if not url:
            continue
        headers = response.get("headers") or {}
        body = response.get("body_text") or response.get("body") or ""
        match = fingerprint_response(headers, str(body) if body else None)
        if match is None:
            continue
        finding = fingerprint_to_finding(match, url=url)
        finding.setdefault("analyzer_key", "waf_fingerprint_analyzer")
        finding.setdefault("phase", "discover")
        findings.append(finding)
    return findings


def waf_challenge_detector(
    responses: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    from src.detection.waf import assess_for_engine

    findings: list[dict[str, Any]] = []
    for response in responses:
        url = str(response.get("url", "")).strip()
        if not url:
            continue
        headers = response.get("headers") or {}
        body = response.get("body_text") or response.get("body") or ""
        status = response.get("status_code")
        assessment = assess_for_engine(
            headers, str(body) if body else None, status_code=status
        )
        if not assessment.get("is_challenge"):
            continue
        finding = {
            "url": url,
            "indicator": "waf_challenge_page",
            "summary": (
                f"Challenge page detected ({assessment.get('challenge_type')}) "
                f"behind {assessment.get('waf_name')}"
            ),
            "severity": "info",
            "confidence": round(assessment.get("confidence", 0.0), 3),
            "waf_name": assessment.get("waf_name"),
            "challenge_type": assessment.get("challenge_type"),
            "bypass_strategies": assessment.get("bypass_strategies", []),
        }
        finding.setdefault("analyzer_key", "waf_challenge_detector")
        finding.setdefault("phase", "discover")
        findings.append(finding)
    return findings


# ---------------------------------------------------------------------------
# Stateful detectors
# ---------------------------------------------------------------------------


def csrf_entropy_analyzer(
    responses: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    from src.detection.stateful import csrf_findings_from_observations

    observations: list[dict[str, Any]] = []
    for response in responses:
        url = str(response.get("url", "")).strip()
        if not url:
            continue
        tokens = response.get("csrf_token_samples") or response.get("csrf_tokens") or []
        if not tokens:
            continue
        observations.append({"url": url, "tokens": tokens, "field": "csrf_token"})
    return csrf_findings_from_observations(observations)


def session_fixation_detector(
    responses: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    from src.detection.stateful import fixation_findings_from_observations

    observations: list[dict[str, Any]] = []
    for response in responses:
        url = str(response.get("url", "")).strip()
        if not url:
            continue
        observations.append(
            {
                "url": url,
                "pre_auth_token": response.get("pre_auth_token"),
                "post_auth_token": response.get("post_auth_token"),
            }
        )
    return fixation_findings_from_observations(observations)


def rate_limit_adaptive_prober(
    responses: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    from src.detection.stateful import adapt_rate_limit_observations

    findings: list[dict[str, Any]] = []
    for response in responses:
        url = str(response.get("url", "")).strip()
        if not url:
            continue
        samples = response.get("rate_limit_samples") or []
        if not samples:
            continue
        result = adapt_rate_limit_observations(url=url, samples=samples)
        finding = result.to_dict()
        finding.setdefault("analyzer_key", "rate_limit_adaptive_prober")
        finding.setdefault("phase", "validate")
        findings.append(finding)
    return findings


def race_concurrent_mutator(
    responses: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Pure-data variant — the actual concurrent firing is a runtime concern.

    This analyzer consumes pre-computed ``race_observations`` items on the
    response dicts (status code counts collected elsewhere in the
    pipeline) and emits the corresponding detection finding.
    """

    findings: list[dict[str, Any]] = []
    for response in responses:
        url = str(response.get("url", "")).strip()
        if not url:
            continue
        observation = response.get("race_observation")
        if not isinstance(observation, dict):
            continue
        fired = int(observation.get("fired_concurrent", 0))
        success = int(observation.get("success_count", 0))
        failure = int(observation.get("failure_count", 0))
        drift = bool(observation.get("drift_observed"))
        finding = {
            "url": url,
            "indicator": "race_condition_concurrent_probe",
            "summary": (
                f"{success}/{fired} concurrent requests succeeded — TOCTOU candidate"
                if drift
                else f"{success}/{fired} concurrent requests completed (no drift)"
            ),
            "severity": "high" if drift else "medium",
            "confidence": round(0.5 + (success / max(1, fired)) * 0.4, 3),
            "fired_concurrent": fired,
            "success_count": success,
            "failure_count": failure,
            "drift_observed": drift,
        }
        finding.setdefault("analyzer_key", "race_concurrent_mutator")
        finding.setdefault("phase", "validate")
        findings.append(finding)
    return findings


# ---------------------------------------------------------------------------
# Helpers for the bindings module
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# API-specific detection handlers (REST HPP, GraphQL, rate-limit diff,
# JWT claim integrity, WebSocket message security)
# ---------------------------------------------------------------------------


def api_rest_param_pollution(
    responses: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Adapter that surfaces REST parameter pollution observations.

    Each response may carry an ``hpp_observations`` list (typically
    produced by the HPP replay harness). The adapter delegates to
    :func:`rest_param_pollution_findings_from_observations` so the
    detector logic stays in :mod:`src.detection.api`.
    """

    from src.detection.api import rest_param_pollution_findings_from_observations

    findings: list[dict[str, Any]] = []
    for response in responses:
        url = str(response.get("url", "")).strip()
        if not url:
            continue
        observations = response.get("hpp_observations") or response.get("rest_hpp_observations")
        if not observations:
            continue
        for finding in rest_param_pollution_findings_from_observations(observations):
            finding.setdefault("analyzer_key", "api_rest_param_pollution")
            finding.setdefault("phase", "analyze")
            if "url" not in finding and url:
                finding["url"] = url
            findings.append(finding)
    return findings


def api_graphql_introspection(
    responses: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Adapter that surfaces GraphQL introspection-query presence signals.

    Each response may carry a ``graphql_introspection_observations``
    list (the recorded body / headers / query of a GraphQL probe).
    """

    from src.detection.api import graphql_introspection_findings_from_observations

    findings: list[dict[str, Any]] = []
    for response in responses:
        url = str(response.get("url", "")).strip()
        if not url:
            continue
        observations = response.get("graphql_introspection_observations") or []
        if not observations:
            continue
        for finding in graphql_introspection_findings_from_observations(observations):
            finding.setdefault("analyzer_key", "api_graphql_introspection")
            finding.setdefault("phase", "analyze")
            if "url" not in finding and url:
                finding["url"] = url
            findings.append(finding)
    return findings


def api_rate_limit_differential(
    responses: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Adapter that computes per-endpoint rate-limit profiles and diffs them.

    Each response may carry a ``rate_limit_observations`` list. The
    adapter builds per-endpoint profiles and converts them into
    findings.
    """

    from src.detection.api import (
        build_endpoint_profiles,
        endpoint_profiles_to_findings,
    )

    observations: list[Any] = []
    for response in responses:
        url = str(response.get("url", "")).strip()
        if not url:
            continue
        items = response.get("rate_limit_observations") or []
        if not items:
            continue
        for item in items:
            if isinstance(item, dict) and "url" not in item:
                item = {**item, "url": item.get("url") or url}
            observations.append(item)

    if not observations:
        return []

    profiles = build_endpoint_profiles(observations)
    findings: list[dict[str, Any]] = []
    for finding in endpoint_profiles_to_findings(profiles):
        finding.setdefault("analyzer_key", "api_rate_limit_differential")
        finding.setdefault("phase", "analyze")
        findings.append(finding)
    return findings


def api_jwt_claim_integrity(
    responses: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Adapter that inspects captured JWTs for pre-signing manipulation surfaces."""

    from src.detection.api import jwt_claim_findings_from_observations

    findings: list[dict[str, Any]] = []
    for response in responses:
        url = str(response.get("url", "")).strip()
        if not url:
            continue
        observations = response.get("jwt_observations") or response.get("jwt_claim_observations")
        if not observations:
            continue
        for finding in jwt_claim_findings_from_observations(observations):
            finding.setdefault("analyzer_key", "api_jwt_claim_integrity")
            finding.setdefault("phase", "analyze")
            if "url" not in finding and url:
                finding["url"] = url
            findings.append(finding)
    return findings


def api_websocket_message_security(
    responses: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Adapter that inspects captured WebSocket frames."""

    from src.detection.api import websocket_message_findings_from_observations

    findings: list[dict[str, Any]] = []
    for response in responses:
        url = str(response.get("url", "")).strip()
        if not url:
            continue
        observations = response.get("websocket_frame_observations") or []
        if not observations:
            continue
        for finding in websocket_message_findings_from_observations(observations):
            finding.setdefault("analyzer_key", "api_websocket_message_security")
            finding.setdefault("phase", "analyze")
            if "url" not in finding and url:
                finding["url"] = url
            findings.append(finding)
    return findings


# ---------------------------------------------------------------------------
# Helpers for the bindings module
# ---------------------------------------------------------------------------


def list_handler_keys() -> tuple[str, ...]:
    return (
        "js_sink_source_analyzer",
        "wasm_module_introspector",
        "prototype_pollution_walker",
        "dom_runtime_analyzer",
        "waf_fingerprint_analyzer",
        "waf_challenge_detector",
        "csrf_entropy_analyzer",
        "session_fixation_detector",
        "rate_limit_adaptive_prober",
        "race_concurrent_mutator",
        "api_rest_param_pollution",
        "api_graphql_introspection",
        "api_rate_limit_differential",
        "api_jwt_claim_integrity",
        "api_websocket_message_security",
    )


def get_handler(key: str) -> Any:
    table: dict[str, Any] = {
        "js_sink_source_analyzer": js_sink_source_analyzer,
        "wasm_module_introspector": wasm_module_introspector,
        "prototype_pollution_walker": prototype_pollution_walker,
        "dom_runtime_analyzer": dom_runtime_analyzer,
        "waf_fingerprint_analyzer": waf_fingerprint_analyzer,
        "waf_challenge_detector": waf_challenge_detector,
        "csrf_entropy_analyzer": csrf_entropy_analyzer,
        "session_fixation_detector": session_fixation_detector,
        "rate_limit_adaptive_prober": rate_limit_adaptive_prober,
        "race_concurrent_mutator": race_concurrent_mutator,
        "api_rest_param_pollution": api_rest_param_pollution,
        "api_graphql_introspection": api_graphql_introspection,
        "api_rate_limit_differential": api_rate_limit_differential,
        "api_jwt_claim_integrity": api_jwt_claim_integrity,
        "api_websocket_message_security": api_websocket_message_security,
    }
    return table.get(key)


__all__ = [
    "api_graphql_introspection",
    "api_jwt_claim_integrity",
    "api_rate_limit_differential",
    "api_rest_param_pollution",
    "api_websocket_message_security",
    "csrf_entropy_analyzer",
    "dom_runtime_analyzer",
    "get_handler",
    "js_sink_source_analyzer",
    "list_handler_keys",
    "prototype_pollution_walker",
    "race_concurrent_mutator",
    "rate_limit_adaptive_prober",
    "session_fixation_detector",
    "waf_challenge_detector",
    "waf_fingerprint_analyzer",
    "wasm_module_introspector",
]
