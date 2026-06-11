import logging
from typing import Any

from src.core.models import ValidationResult
from src.execution.validators.interfaces import Validator
from src.execution.validators.registry import VALIDATOR_ORDER
from src.execution.validators.validators.cache_poison import validate_cache_poison
from src.execution.validators.validators.cors import validate_cors_endpoint
from src.execution.validators.validators.csrf import validate as validate_csrf
from src.execution.validators.validators.file_upload import (
    validate as validate_file_upload,
)
from src.execution.validators.validators.graphql import validate_graphql_endpoint
from src.execution.validators.validators.idor import validate as validate_idor
from src.execution.validators.validators.jwt import validate_jwt_token
from src.execution.validators.validators.race import validate_race_condition
from src.execution.validators.validators.redirect import (
    validate as validate_redirect,
)
from src.execution.validators.validators.ssrf import validate as validate_ssrf
from src.execution.validators.validators.ssti import validate as validate_ssti
from src.execution.validators.validators.token_reuse import (
    validate as validate_token_reuse,
)
from src.execution.validators.validators.xss import validate as validate_xss

logger = logging.getLogger(__name__)

# R1: The ``Validator`` Protocol is the canonical interface. The
# ``ValidationStrategy`` Protocol is the engine interface. The
# adapter helpers below keep both call styles working while
# delegating to the engine registry as the single source of truth.

_BASE_RUNNERS: dict[str, Any] = {
    "redirect": validate_redirect,
    "ssrf": validate_ssrf,
    "token_reuse": validate_token_reuse,
    "idor": validate_idor,
    "csrf": validate_csrf,
    "xss": validate_xss,
    "ssti": validate_ssti,
    "file_upload": validate_file_upload,
    "cors": validate_cors_endpoint,
    "jwt_weakness": validate_jwt_token,
    "cache_poisoning": validate_cache_poison,
    "graphql_abuse": validate_graphql_endpoint,
    "race_condition": validate_race_condition,
}


# Stub validators for registered but not-yet-implemented validators
def _stub_validator(name: str) -> Validator:
    """Create a stub validator that returns a no-op result and logs a warning."""

    def validate(target: dict[str, Any], context: dict[str, Any]) -> ValidationResult:
        logger.warning(
            "Stub validator '%s' invoked on %s — this is a no-op placeholder",
            name,
            target.get("url", "<unknown-url>"),
        )
        return ValidationResult(
            validator=name,
            category=name,
            url=target.get("url", ""),
            status="skipped",
            confidence=0.0,
            in_scope=True,
            scope_reason=f"{name} validator not yet implemented",
        )

    return validate


_RUNNERS: dict[str, Any] = dict(_BASE_RUNNERS)
for _validator_name in VALIDATOR_ORDER:
    _RUNNERS.setdefault(_validator_name, _stub_validator(_validator_name))


def _engine_strategy_runner(name: str) -> Validator | None:
    """R1 adapter: return a ``Validator``-shaped callable backed by the
    engine ``ValidationStrategy`` for the given validator name.

    Returns None when the engine has no strategy registered for ``name``
    (e.g. facade-only validators).
    """
    try:
        from src.execution.validators.engine._runner import (
            build_validator_registry,
        )
    except ImportError as exc:
        logger.debug("Engine runner import failed, skipping strategy adapter: %s", exc)
        return None
    registry = build_validator_registry()
    spec = registry.get(name)
    if spec is None:
        return None

    def _run(target: dict[str, Any], context: dict[str, Any]) -> ValidationResult:
        from src.execution.validators.engine._base import ValidationContext
        from src.execution.validators.engine._http_client import (
            ValidationHttpClient,
            ValidationHttpConfig,
        )
        from src.execution.validators.engine_helpers import collect_scope_hosts
        from src.pipeline.retry import RetryPolicy

        http_client = ValidationHttpClient(
            ValidationHttpConfig(
                timeout_seconds=int(context.get("timeout_seconds", 10) or 10),
                max_response_bytes=int(context.get("max_response_bytes", 120000) or 120000),
                retry_policy=RetryPolicy(max_attempts=1, initial_backoff_seconds=0.0),
            )
        )
        engine_context = ValidationContext(
            analysis_results=dict(context.get("analysis_results") or {}),
            ranked_priority_urls=list(context.get("ranked_priority_urls") or []),
            callback_context=dict(context.get("callback_context") or {}),
            token_replay=dict(context.get("token_replay") or {}),
            runtime_inputs=dict(context.get("runtime_inputs") or {}),
            scope_hosts=set(
                context.get("scope_hosts")
                or collect_scope_hosts(
                    context.get("analysis_results", {}) or {},
                    context.get("ranked_priority_urls", []) or [],
                    context.get("runtime_inputs", {}) or {},
                )
            ),
            http_client=http_client,
            active_probe_enabled=bool(context.get("active_probe_enabled", False)),
            per_validator_limit=int(context.get("per_validator_limit", 1) or 1),
            selector_config=dict(context.get("selector_config") or {}),
        )
        try:
            validator = spec.strategy_factory()
            findings, _errors = validator.run(engine_context)
        except Exception as exc:  # noqa: BLE001 — broad catch intentional, engine strategy may raise arbitrary errors
            logger.warning("Engine strategy '%s' failed: %s", name, exc)
            findings = []
        for finding in findings:
            if str(finding.get("url", "")) == str(target.get("url", "")) or not target.get("url"):
                return ValidationResult(
                    validator=name,
                    category=str(finding.get("category", name)),
                    url=str(finding.get("url", target.get("url", ""))),
                    status=str(finding.get("validation_state", "inconclusive")),
                    confidence=float(finding.get("confidence", 0.0) or 0.0),
                    in_scope=bool(finding.get("in_scope", True)),
                    scope_reason=str(finding.get("scope_reason", "scope_evaluated")),
                    evidence=dict(finding.get("evidence") or {}),
                )
        return ValidationResult(
            validator=name,
            category=name,
            url=str(target.get("url", "")),
            status="inconclusive",
            confidence=0.0,
            in_scope=True,
            scope_reason="no_matching_finding",
        )

    return _run


# R1: merge the engine plugin registry into the facade registry so a
# single source of truth (``build_validator_registry``) drives both the
# engine runner and the ``validate_target`` / ``validate_many`` facade.
for _name in list(VALIDATOR_ORDER):
    if _name in _RUNNERS:
        continue
    _strategy_runner = _engine_strategy_runner(_name)
    if _strategy_runner is not None:
        _RUNNERS[_name] = _strategy_runner

VALIDATOR_REGISTRY: dict[str, Any] = {name: _RUNNERS[name] for name in VALIDATOR_ORDER}

__all__ = [
    "VALIDATOR_REGISTRY",
    "validate_idor",
    "validate_redirect",
    "validate_ssrf",
    "validate_token_reuse",
    "validate_csrf",
    "validate_xss",
    "validate_ssti",
    "validate_file_upload",
]
