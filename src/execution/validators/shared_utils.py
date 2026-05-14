"""Shared utilities for building validation findings and applying probe results.

Provides helpers for constructing standardized finding dicts, marking
out-of-scope results, and applying HTTP probe outcomes to findings.
"""

from typing import Any

from src.decision.attack_selection import select_validation_actions
from src.execution.validators.validators.shared import build_validation_explanation


def build_base_finding(
    *,
    schema_version: str,
    validator_name: str,
    category: str,
    url: str,
    in_scope: bool,
    scope_reason: str,
    confidence: float,
    validation_state: str,
    signals: list[str],
    score: int,
    timeout_seconds: int,
    scope_hosts: set[str],
    selector_config: dict[str, Any],
    evidence: dict[str, Any] | None = None,
    edge_case_notes: list[str] | None = None,
) -> dict[str, Any]:
    """Build a standardized validation finding dictionary.

    Args:
        schema_version: Validation result schema version.
        validator_name: Name of the validator that produced this finding.
        category: Finding category (e.g., 'idor', 'ssrf', 'open_redirect').
        url: Target URL.
        in_scope: Whether the target is within authorized scope.
        scope_reason: Reason for the scope determination.
        confidence: Confidence score (0.0-1.0).
        validation_state: Current validation state.
        signals: List of detected signal names.
        score: Numeric severity score.
        timeout_seconds: HTTP timeout used for probes.
        scope_hosts: Set of authorized scope hosts.
        selector_config: Attack selection configuration.
        evidence: Optional evidence dictionary.
        edge_case_notes: Optional list of edge case considerations.

    Returns:
        Standardized finding dict conforming to the validation schema.
    """
    evidence_map = evidence or {}
    # Build human-readable explanation for the validation result
    explanation = build_validation_explanation(
        category=category,
        validation_state=validation_state,
        confidence=confidence,
        url=url,
        signals=signals,
        edge_case_notes=edge_case_notes,
    )
    return {
        "schema_version": schema_version,
        "validator": validator_name,
        "category": category,
        "status": "ok" if in_scope else "skipped",
        "url": url,
        "in_scope": in_scope,
        "scope_reason": scope_reason,
        "score": int(score),
        "confidence": round(float(confidence), 2),
        "validation_state": validation_state,
        "signals": sorted({signal for signal in signals if signal}),
        "evidence": evidence_map,
        "explanation": explanation,
        "http": {
            "requested_url": url,
            "final_url": url,
            "status_code": None,
            "redirect_count": 0,
            "attempts": 0,
            "timeout_seconds": timeout_seconds,
            "latency_seconds": 0.0,
            "error": "",
        },
        "error": {},
        "validation_actions": select_validation_actions(
            url=url,
            params=_selector_params(evidence_map),
            signals=signals,
            scope_hosts=scope_hosts,
            config=selector_config,
        ),
    }


def mark_out_of_scope(finding: dict[str, Any]) -> None:
    finding["error"] = {"code": "out_of_scope", "message": "URL is outside the validation scope."}


def apply_probe_result(
    *,
    finding: dict[str, Any],
    probe: dict[str, Any],
    error_code: str = "http_probe_failed",
) -> dict[str, Any] | None:
    finding["http"] = probe
    if probe.get("ok"):
        return None
    finding["status"] = "error"
    finding["error"] = {
        "code": error_code,
        "message": str(probe.get("error") or "request failed"),
    }
    return {
        "validator": finding.get("validator", ""),
        "url": finding.get("url", ""),
        "error": finding["error"],
    }


def _selector_params(evidence: dict[str, Any]) -> list[str]:
    params: set[str] = set()
    for value in evidence.values():
        if isinstance(value, list):
            params.update(str(item) for item in value if str(item))
        elif isinstance(value, str) and value:
            params.add(value)
    return sorted(params)
