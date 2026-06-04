import logging
from typing import TYPE_CHECKING, Any

from src.execution import (
    active_manifest,
    exploiters,
    isolated,
    scenario_engine,
)

if TYPE_CHECKING:
    from src.execution import validators as _validators_typing

logger = logging.getLogger(__name__)

try:
    from src.execution import validators

    _VALIDATORS_AVAILABLE = True
    _VALIDATOR_IMPORT_ERROR: Exception | None = None
except Exception as exc:
    # Validator imports are intentionally optional during child-process bootstrap.
    validators = None  # type: ignore[assignment]
    _VALIDATORS_AVAILABLE = False
    _VALIDATOR_IMPORT_ERROR = exc
    logger.warning(
        "Failed to import validators: %s. This is normal during child-process bootstrap, "
        "but may indicate missing dependencies if it happens in the main process.",
        exc,
        exc_info=True,
    )


# Re-export submodules so consumers can do `from src.execution import active_manifest`.
__all__ = [
    "active_manifest",
    "exploiters",
    "isolated",
    "scenario_engine",
    "validators",
]


def __getattr__(name: str) -> Any:
    """Lazily re-export public names from the submodules.

    This avoids ``from X import *`` while preserving backward compatibility for any
    consumer that does ``from src.execution import SomeSymbol``.
    """
    if name in _ACTIVE_MANIFEST_NAMES:
        return getattr(active_manifest, name)
    if name in _EXPLOITERS_NAMES:
        return getattr(exploiters, name)
    if name in _ISOLATED_NAMES:
        return getattr(isolated, name)
    if name in _SCENARIO_ENGINE_NAMES:
        return getattr(scenario_engine, name)
    if name in _VALIDATORS_NAMES:
        if not _VALIDATORS_AVAILABLE:
            raise AttributeError(
                f"module {__name__!r} has no attribute {name!r} "
                f"(validators unavailable: {_VALIDATOR_IMPORT_ERROR})"
            )
        return getattr(validators, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


_ACTIVE_MANIFEST_NAMES = (
    "ActiveCapability",
    "ActiveCheckManifest",
    "ActiveExecutionBudget",
    "ActiveInputKind",
    "ActiveIOContract",
    "ActiveManifestRegistry",
    "ActiveResultEncoding",
    "DEFAULT_ACTIVE_MANIFEST_REGISTRY",
    "build_default_active_manifest_registry",
    "get_active_manifest",
    "query_active_manifests",
    "reset_active_manifest_registry",
)

_EXPLOITERS_NAMES = (
    "AUTH_REPLAY_MODES",
    "build_chain_simulation",
    "build_curl_poc",
    "build_proof_bundle",
    "build_python_poc",
    "enrich_behavior_finding",
    "replay_headers_for_mode",
)

_ISOLATED_NAMES = (
    "IsolatedExecutionResult",
    "IsolatedResponseCacheFactory",
    "PROCESS_JOIN_TIMEOUT",
    "replace_unpicklable_response_caches",
    "run_callable_isolated",
)

_SCENARIO_ENGINE_NAMES = (
    "ScenarioExecutionEngine",
    "StepResultsDict",
    "Transport",
)

_VALIDATORS_NAMES = (
    "VALIDATOR_REGISTRY",
    "ValidationStatus",
    "Validator",
    "execute_validation_runtime",
    "validate_many",
    "validate_target",
)
