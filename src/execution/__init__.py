import logging
from typing import TYPE_CHECKING, Any

from src.execution import (
    active_manifest,
    exploiters,
    isolated,
    request_executor,
    scenario_engine,
)

if TYPE_CHECKING:
    from src.execution import validators as _validators_typing

logger = logging.getLogger(__name__)

try:
    from src.execution import validators

    _VALIDATORS_AVAILABLE = True
    _VALIDATOR_IMPORT_ERROR: Exception | None = None
except ImportError as exc:
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


# ---------------------------------------------------------------------------
# Module self-description
# ---------------------------------------------------------------------------

from src.core.utils.shared import (  # noqa: E402
    ModuleMeta,
    register_module_meta,
)

MODULE_META = ModuleMeta(
    name="execution",
    version="3.1.0",
    description=(
        "Step execution, scenario engine, auth flows, remediators, "
        "and validators. Executes active checks and exploitation steps "
        "with rollback, scope enforcement, and result collection."
    ),
    layer="execution",
    submodules=(
        "auth",
        "executors",
        "exploiters",
        "frontier",
        "remediators",
        "steps",
        "templates",
        "validators",
    ),
    public_api=(
        "active_manifest",
        "exploiters",
        "isolated",
        "scenario_engine",
        "validators",
    ),
    depends_on=("core", "recon", "analysis", "decision"),
    entry_points=(),
    health_check="health_check",
)


def health_check() -> dict[str, Any]:
    """Verify execution subsystem health.

    Returns:
        Dict with ``status`` (``"ok"`` / ``"degraded"``), ``module``,
        ``version``, and optional ``details`` / ``errors``.
    """
    errors: list[str] = []
    try:
        from src.execution.scenario_engine import ScenarioExecutionEngine  # noqa: F401

        engine_ok = True
    except ImportError as exc:
        engine_ok = False
        errors.append(f"ScenarioExecutionEngine unavailable: {exc}")
    try:
        from src.execution.validators.registry import VALIDATOR_REGISTRY  # noqa: F401

        validators_ok = True
    except ImportError as exc:
        validators_ok = False
        errors.append(f"VALIDATOR_REGISTRY unavailable: {exc}")
    status = "ok" if (engine_ok and validators_ok) else "degraded"
    return {
        "status": status,
        "module": "execution",
        "version": "3.1.0",
        "details": {
            "scenario_engine": "available" if engine_ok else "unavailable",
            "validators": "available" if validators_ok else "unavailable",
        },
        **({"errors": errors} if errors else {}),
    }


register_module_meta(MODULE_META)

# ---------------------------------------------------------------------------
# Re-export submodules (unchanged)
# ---------------------------------------------------------------------------


# Re-export submodules so consumers can do `from src.execution import active_manifest`.
__all__ = [
    "ExecutionRequestWorker",
    "active_manifest",
    "exploiters",
    "isolated",
    "request_executor",
    "scenario_engine",
    "validators",
]


def __getattr__(name: str) -> Any:
    """Lazily re-export public names from the submodules.

    This avoids ``from X import *`` while preserving backward compatibility for any
    consumer that does ``from src.execution import SomeSymbol``.
    """
    if name in _REQUEST_EXECUTOR_NAMES:
        return getattr(request_executor, name)
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


_REQUEST_EXECUTOR_NAMES = (
    "ActionHandler",
    "ExecutionRequestWorker",
)


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
