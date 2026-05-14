"""Validation engine runner and registry builder."""

from typing import Any

from src.core.contracts.pipeline import TIMEOUT_DEFAULTS, VALIDATION_RUNTIME_SCHEMA_VERSION
from src.core.plugins import list_plugins
from src.execution.validators.engine_helpers import collect_scope_hosts
from src.execution.validators.registry import VALIDATOR_RESULT_KEYS
from src.execution.validators.strategy import ValidationStrategySpec
from src.pipeline.retry import RetryPolicy

from ._base import ValidationContext
from ._http_client import ValidationHttpClient, ValidationHttpConfig

RUNTIME_SCHEMA_VERSION = VALIDATION_RUNTIME_SCHEMA_VERSION


def build_validator_registry() -> dict[str, ValidationStrategySpec]:
    """Build the validator registry mapping names to strategy specs."""
    # Only include keys that are actual validators, excluding support functions and stage runners
    registrations = [
        reg
        for reg in list_plugins("validator")
        if not (
            reg.key.endswith("_candidates")
            or reg.key.startswith("promote_")
            or reg.key in {"access_control", "validation"}
        )
    ]
    return {
        reg.key: ValidationStrategySpec(
            reg.key,
            VALIDATOR_RESULT_KEYS.get(reg.key, f"{reg.key}_validation"),
            reg.provider,
        )
        for reg in registrations
    }


def run_blackbox_validation_engine(
    analysis_results: dict[str, list[dict[str, Any]]],
    ranked_priority_urls: list[dict[str, Any]],
    callback_context: dict[str, Any],
    token_replay: dict[str, Any],
    validation_settings: dict[str, Any] | None = None,
    runtime_inputs: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run the blackbox validation engine with all registered validators."""
    settings = validation_settings or {}
    runtime_inputs = runtime_inputs or {}
    engine_settings = (
        settings.get("blackbox_validation", {})
        if isinstance(settings.get("blackbox_validation", {}), dict)
        else {}
    )

    timeout_seconds = max(
        1, int(engine_settings.get("timeout_seconds", TIMEOUT_DEFAULTS["http_request_seconds"]))
    )
    max_response_bytes = max(1024, int(engine_settings.get("max_response_bytes", 120_000)))
    retry_attempts = max(1, int(engine_settings.get("retry_attempts", 2)))
    retry_backoff_seconds = max(0.0, float(engine_settings.get("retry_backoff_seconds", 0.5)))
    retry_multiplier = max(1.0, float(engine_settings.get("retry_backoff_multiplier", 2.0)))
    per_validator_limit = max(1, int(engine_settings.get("per_validator_limit", 20)))

    http_client = ValidationHttpClient(
        ValidationHttpConfig(
            timeout_seconds=timeout_seconds,
            max_response_bytes=max_response_bytes,
            retry_policy=RetryPolicy(
                max_attempts=retry_attempts,
                initial_backoff_seconds=retry_backoff_seconds,
                backoff_multiplier=retry_multiplier,
                max_backoff_seconds=max(
                    0.0, float(engine_settings.get("retry_max_backoff_seconds", 4.0))
                ),
            ),
        )
    )
    scope_hosts = collect_scope_hosts(analysis_results, ranked_priority_urls, runtime_inputs)
    context = ValidationContext(
        analysis_results=analysis_results,
        ranked_priority_urls=ranked_priority_urls,
        callback_context=callback_context,
        token_replay=token_replay,
        runtime_inputs=runtime_inputs,
        scope_hosts=scope_hosts,
        http_client=http_client,
        active_probe_enabled=bool(engine_settings.get("active_probe_enabled", True)),
        per_validator_limit=per_validator_limit,
        selector_config=(
            engine_settings.get("selector", {})
            if isinstance(engine_settings.get("selector", {}), dict)
            else {}
        ),
    )

    registry = build_validator_registry()
    validator_specs, selection_errors = _resolve_validator_specs(engine_settings, registry)
    raw_enabled = engine_settings.get("enabled_validators", [])
    explicit_validator_selection = isinstance(raw_enabled, list) and bool(raw_enabled)
    requested_validators = (
        sorted({str(raw_name).strip().lower() for raw_name in raw_enabled if str(raw_name).strip()})
        if explicit_validator_selection
        else []
    )

    results: dict[str, list[dict[str, Any]]] = {}
    errors: list[dict[str, Any]] = list(selection_errors)
    for spec in validator_specs:
        validator = spec.strategy_factory()
        validator_findings, validator_errors = validator.run(context)
        results[spec.result_key] = validator_findings
        errors.extend(validator_errors)

    return {
        "schema_version": RUNTIME_SCHEMA_VERSION,
        "results": results,
        "errors": errors,
        "settings": {
            "timeout_seconds": timeout_seconds,
            "retry_attempts": retry_attempts,
            "retry_backoff_seconds": retry_backoff_seconds,
            "active_probe_enabled": context.active_probe_enabled,
            "per_validator_limit": per_validator_limit,
            "scope_hosts_count": len(scope_hosts),
            "validator_selection_explicit": explicit_validator_selection,
            "requested_validators": requested_validators,
            "enabled_validators": [spec.name for spec in validator_specs],
            "available_validators": sorted(registry),
        },
    }


def _resolve_validator_specs(
    engine_settings: dict[str, Any],
    registry: dict[str, ValidationStrategySpec],
) -> tuple[list[ValidationStrategySpec], list[dict[str, Any]]]:
    """Resolve validator specs from engine settings, falling back to all validators."""
    raw_enabled = engine_settings.get("enabled_validators", [])
    if not isinstance(raw_enabled, list) or not raw_enabled:
        return list(registry.values()), []

    selected: list[ValidationStrategySpec] = []
    errors: list[dict[str, Any]] = []
    for raw_name in raw_enabled:
        name = str(raw_name).strip().lower()
        if not name:
            continue
        spec = registry.get(name)
        if spec is None:
            errors.append(
                {
                    "validator": name,
                    "url": "",
                    "error": {
                        "code": "unknown_validator",
                        "message": f"Validator '{name}' is not registered.",
                    },
                }
            )
        else:
            selected.append(spec)
    return selected, errors
