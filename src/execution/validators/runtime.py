"""Validation runtime orchestrator for executing all validation checks.

Coordinates callback target description, token replay summary, blackbox
validation engine, API key validation, and IDOR candidate promotion into
a unified validation results dictionary.
"""

import time
from typing import Any

from src.core.contracts.pipeline import VALIDATION_RUNTIME_SCHEMA_VERSION
from src.core.plugins import resolve_plugin
from src.execution.validators.callback import describe_callback_target
from src.execution.validators.engine import (
    build_token_replay_summary,
    run_blackbox_validation_engine,
)

VALIDATOR = "validator"


def execute_validation_runtime(
    analysis_results: dict[str, list[dict[str, Any]]],
    ranked_priority_urls: list[dict[str, Any]],
    validation_settings: dict[str, Any] | None = None,
    mode: str = "default",
    runtime_inputs: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Execute the full validation runtime pipeline using registered providers."""
    stage_started = time.monotonic()
    callback_context = describe_callback_target(validation_settings)
    token_replay = build_token_replay_summary(analysis_results)
    engine_output = run_blackbox_validation_engine(
        analysis_results,
        ranked_priority_urls,
        callback_context,
        token_replay,
        validation_settings,
        runtime_inputs,
    )
    results = dict(engine_output.get("results", {}))
    selection_explicit = bool(
        engine_output.get("settings", {}).get("validator_selection_explicit", False)
    )
    enabled_validators = {
        str(name).strip().lower()
        for name in engine_output.get("settings", {}).get("enabled_validators", [])
        if str(name).strip()
    }

    def _is_enabled(validator_name: str) -> bool:
        # Empty enabled set means "all validators" only for implicit/default selection.
        if selection_explicit:
            return validator_name in enabled_validators
        return not enabled_validators or validator_name in enabled_validators

    # IDOR
    if _is_enabled("idor"):
        idor_results = list(results.get("idor_validation") or [])
        if not idor_results:
            try:
                validate_idor = resolve_plugin(VALIDATOR, "idor_candidates")
                idor_results = validate_idor(analysis_results, token_replay)
            except KeyError:
                pass
        results["idor_validation"] = idor_results

    # CSRF
    if _is_enabled("csrf"):
        csrf_results = list(results.get("csrf_validation") or [])
        if not csrf_results:
            try:
                validate_csrf = resolve_plugin(VALIDATOR, "csrf_candidates")
                csrf_results = validate_csrf(analysis_results, callback_context)
            except KeyError:
                pass
        results["csrf_validation"] = csrf_results

    # XSS
    if _is_enabled("xss"):
        xss_results = list(results.get("xss_validation") or [])
        if not xss_results:
            try:
                validate_xss = resolve_plugin(VALIDATOR, "xss_candidates")
                xss_results = validate_xss(analysis_results, callback_context)
            except KeyError:
                pass
        results["xss_validation"] = xss_results

    # API Keys
    try:
        validate_api_keys = resolve_plugin(VALIDATOR, "api_key_candidates")
        api_key_results = validate_api_keys(runtime_inputs, validation_settings)
        results["api_key_validation"] = api_key_results
    except KeyError:
        pass

    errors = engine_output.get("errors", [])
    duration = round(time.monotonic() - stage_started, 3)
    metric_payload = {
        "status": "ok" if not errors else "partial",
        "duration_seconds": duration,
        "error_count": len(errors),
    }

    # Promote results
    verified_exploits = []
    try:
        promote_idor = resolve_plugin(VALIDATOR, "promote_idor_evidence")  # Not yet registered
        verified_exploits.extend(promote_idor(results.get("idor_validation", [])))
    except KeyError:
        # Fallback to local import if not in registry yet (or just skip for now)
        from src.execution.validators.validators.idor import promote_evidence_backed_results

        verified_exploits.extend(
            promote_evidence_backed_results(results.get("idor_validation", []))
        )

    verified_exploits.extend(promote_behavior_confirmations(analysis_results))

    return {
        "schema_version": engine_output.get("schema_version", VALIDATION_RUNTIME_SCHEMA_VERSION),
        "mode": mode,
        "results": results,
        "verified_exploits": verified_exploits,
        "callback_context": callback_context,
        "token_replay": token_replay,
        "errors": errors,
        "settings": engine_output.get("settings", {}),
        "metric": metric_payload,
        "metrics": metric_payload,
    }


def promote_behavior_confirmations(
    analysis_results: dict[str, list[dict[str, Any]]],
) -> list[dict[str, Any]]:
    promoted = []
    for item in analysis_results.get("behavior_analysis_layer", []):
        if not item.get("confirmed"):
            continue
        impact_level = str(item.get("impact_level", "")).lower()
        severity = (
            "high" if impact_level == "high" or item.get("trust_boundary_shift") else "medium"
        )
        promoted.append(
            {
                "title": "Confirmed behavior deviation",
                "severity": severity,
                "url": item.get("url", ""),
                "confidence": item.get("confidence", 0),
                "evidence": {
                    "parameter": item.get("parameter", ""),
                    "variant": item.get("variant", ""),
                    "body_similarity": item.get("diff", {}).get("body_similarity"),
                    "trust_boundary_shift": item.get("trust_boundary_shift", False),
                    "flow_transition": item.get("flow_transition", {}),
                    "impact_level": impact_level,
                },
            }
        )
    return promoted[:10]
