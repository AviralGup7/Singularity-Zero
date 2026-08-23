"""Startup registration of protocol implementations.

This module registers all concrete implementations against the protocols
defined in cross_package_protocols.py. It should be called once during
application startup (e.g., from the FastAPI lifespan or CLI entry point).

This module is the ONLY place where cross-package imports are allowed
for registration purposes. It acts as the composition root.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

# Security-critical: a missing bind must be retryable and must not
# silently authorize an unauthenticated scan.
_CRITICAL_BINDINGS = frozenset({"oauth_authenticator_cls"})

_bound: set[str] = set()
_failed: dict[str, str] = {}
_REGISTERED = False


def binding_status() -> dict[str, object]:
    """Return bound names and last failure reasons (observable imports)."""
    return {
        "bound": sorted(_bound),
        "failed": dict(_failed),
        "critical_missing": sorted(_CRITICAL_BINDINGS - _bound),
        "complete": not _failed and _CRITICAL_BINDINGS <= _bound,
    }


def reset_startup_registration() -> None:
    """Clear bind bookkeeping and protocol-registry globals (reload/tests)."""
    global _REGISTERED
    _bound.clear()
    _failed.clear()
    _REGISTERED = False
    from src.core.contracts.protocol_registry import reset_protocol_registry

    reset_protocol_registry()


def _try_bind(name: str, loader: object, *, critical: bool = False) -> None:
    """Run *loader* once; retry on later register_all calls if it failed."""
    if name in _bound:
        return
    try:
        loader()  # type: ignore[operator]
    except ImportError as exc:
        _failed[name] = str(exc)
        if critical or name in _CRITICAL_BINDINGS:
            logger.error("Critical protocol binding %s unavailable: %s", name, exc)
        else:
            logger.warning("Protocol binding %s unavailable: %s", name, exc)
        return
    _bound.add(name)
    _failed.pop(name, None)
    logger.info("Registered protocol binding %s", name)


def register_all_implementations() -> None:
    """Register all protocol implementations at startup.

    Idempotent per binding. Missing optional imports stay visible in
    ``binding_status()`` and are retried on the next call. ``_REGISTERED``
    is True only when every attempted bind succeeded.
    """
    global _REGISTERED

    from src.core.contracts.protocol_registry import (
        register_active_manifest_registry,
        register_analysis_check_options,
        register_analyst_notes,
        register_ast_mutator,
        register_auth_flow_runner_cls,
        register_chameleon_evasion,
        register_corrective_action_registry_cls,
        register_exploit_replay,
        register_fetch_response_provider,
        register_isolated_execution,
        register_lateral_graph_cls,
        register_launcher_manifest,
        register_oauth_authenticator_cls,
        register_passive_check_names,
        register_plugin_artifact_loader,
        register_remediation_scanner_cls,
        register_response_comparator,
        register_retry_policy_cls,
        register_self_healing_controller_cls,
        register_stage_baseline,
        register_tenant_isolation_check,
        register_tool_execution_service_cls,
        register_validation_runtime,
        register_wasm_executor,
    )

    def _bind_ast() -> None:
        from src.fuzzing.ast_mutator import JSONASTMutator

        register_ast_mutator(JSONASTMutator())

    def _bind_wasm() -> None:
        from src.execution.frontier.wasm import execute_sandboxed_plugin

        register_wasm_executor(execute_sandboxed_plugin)

    def _bind_analysis_plugins() -> None:
        from src.analysis.plugins import PASSIVE_CHECK_NAMES, analysis_check_options

        register_analysis_check_options(analysis_check_options)
        register_passive_check_names(PASSIVE_CHECK_NAMES)

    def _bind_lateral_graph() -> None:
        from src.analysis.intelligence.lateral_graph import LateralGraph

        register_lateral_graph_cls(LateralGraph)

    def _bind_fetch_response() -> None:
        from src.analysis.passive.runtime import _get_fetch_response

        register_fetch_response_provider(_get_fetch_response)

    def _bind_response_comparator() -> None:
        from src.analysis.behavior.analysis_support import compare_response_records

        register_response_comparator(compare_response_records)

    def _bind_plugin_artifacts() -> None:
        from src.analysis.behavior import artifacts as _artifacts

        register_plugin_artifact_loader(_artifacts)

    def _bind_chameleon() -> None:
        from src.execution.frontier.chameleon import _chameleon

        register_chameleon_evasion(_chameleon)

    def _bind_exploit_replay() -> None:
        from src.execution.exploiters.exploit_automation import replay_headers_for_mode

        register_exploit_replay(replay_headers_for_mode)

    def _bind_remediation() -> None:
        from src.execution.remediators.remediation_scanner import RemediationScanner

        register_remediation_scanner_cls(RemediationScanner)

    def _bind_self_healing() -> None:
        from src.pipeline.self_healing import (
            CorrectiveActionRegistry,
            SelfHealingController,
        )

        register_self_healing_controller_cls(SelfHealingController)
        register_corrective_action_registry_cls(CorrectiveActionRegistry)

    def _bind_tool_execution() -> None:
        from src.pipeline.services.tool_execution import ToolExecutionService

        register_tool_execution_service_cls(ToolExecutionService)

    def _bind_analyst_notes() -> None:
        from src.pipeline import analyst_notes as _notes

        register_analyst_notes(_notes)

    def _bind_stage_baseline() -> None:
        from src.pipeline.constants.progress import STAGE_BASELINE_PERCENT

        register_stage_baseline(STAGE_BASELINE_PERCENT)

    def _bind_active_manifests() -> None:
        from src.execution.active_manifest import DEFAULT_ACTIVE_MANIFEST_REGISTRY

        register_active_manifest_registry(DEFAULT_ACTIVE_MANIFEST_REGISTRY)

    def _bind_validation_runtime() -> None:
        from src.execution.validators import execute_validation_runtime

        register_validation_runtime(execute_validation_runtime)

    def _bind_isolated() -> None:
        from src.execution.isolated import run_callable_isolated

        register_isolated_execution(run_callable_isolated)

    def _bind_oauth() -> None:
        from src.execution.auth import OAuthAuthenticator
        from src.execution.auth.select import resolve_auth_flow_runner_cls

        register_oauth_authenticator_cls(OAuthAuthenticator)
        register_auth_flow_runner_cls(resolve_auth_flow_runner_cls())

    def _bind_validators_engine() -> None:
        import src.execution.validators.engine._validators  # noqa: F401

    def _bind_retry_policy() -> None:
        from src.pipeline.retry import RetryPolicy

        register_retry_policy_cls(RetryPolicy)

    def _bind_launcher_manifest() -> None:
        from src.dashboard.forensics.launcher import (
            build_launcher_replay_manifest,
            compare_launcher_replay_manifests,
        )

        class _LauncherManifest:
            def build_launcher_replay_manifest(self, *args, **kwargs):
                return build_launcher_replay_manifest(*args, **kwargs)

            def compare_launcher_replay_manifests(self, baseline, new_run):
                return compare_launcher_replay_manifests(baseline, new_run)

        register_launcher_manifest(_LauncherManifest())

    def _bind_tenant_isolation() -> None:
        from src.dashboard.fastapi.routers.targets import is_target_owned_by_tenant

        register_tenant_isolation_check(is_target_owned_by_tenant)

    _try_bind("ast_mutator", _bind_ast)
    _try_bind("wasm_executor", _bind_wasm)
    _try_bind("analysis_plugins", _bind_analysis_plugins)
    _try_bind("lateral_graph_cls", _bind_lateral_graph)
    _try_bind("fetch_response_provider", _bind_fetch_response)
    _try_bind("response_comparator", _bind_response_comparator)
    _try_bind("plugin_artifact_loader", _bind_plugin_artifacts)
    _try_bind("chameleon_evasion", _bind_chameleon)
    _try_bind("exploit_replay", _bind_exploit_replay)
    _try_bind("remediation_scanner_cls", _bind_remediation)
    _try_bind("self_healing", _bind_self_healing)
    _try_bind("tool_execution_service_cls", _bind_tool_execution)
    _try_bind("analyst_notes", _bind_analyst_notes)
    _try_bind("stage_baseline", _bind_stage_baseline)
    _try_bind("active_manifest_registry", _bind_active_manifests)
    _try_bind("validation_runtime", _bind_validation_runtime)
    _try_bind("isolated_execution", _bind_isolated)
    _try_bind("oauth_authenticator_cls", _bind_oauth, critical=True)
    _try_bind("validators_engine", _bind_validators_engine)
    _try_bind("retry_policy_cls", _bind_retry_policy)
    _try_bind("launcher_manifest", _bind_launcher_manifest)
    _try_bind("tenant_isolation_check", _bind_tenant_isolation)

    _REGISTERED = not _failed
    if _REGISTERED:
        logger.info("All protocol implementations registered")
    else:
        logger.warning(
            "Protocol registration incomplete; failed=%s critical_missing=%s",
            sorted(_failed),
            sorted(_CRITICAL_BINDINGS - _bound),
        )


def register_analysis_plugin_hooks() -> None:
    """Register analysis plugin system hooks.

    This is separated from ``register_all_implementations`` so that
    callers who need analysis plugin registration (e.g. the dashboard
    lifespan) can opt in without pulling in the full cross-package
    registration surface.
    """
    try:
        from src.analysis.plugin_registration import register_analysis_hooks

        register_analysis_hooks()
        logger.debug("Registered analysis plugin hooks")
    except ImportError:
        logger.debug("Analysis plugin registration not available")


def register_process_bindings() -> None:
    """Register protocol implementations and plugin hooks for this process.

    Dashboard lifespan and ``src.pipeline.runtime:main`` must call this
    same function so CLI scans and UI-launched scans see identical
    protocol bindings.
    """
    register_all_implementations()
    register_analysis_plugin_hooks()
    register_detection_plugin_hooks()


def register_detection_plugin_hooks() -> None:
    """Register detection plugin system hooks.

    This is separated from ``register_all_implementations`` so that
    callers who need detection plugin registration (e.g. the dashboard
    lifespan) can opt in without pulling in the full cross-package
    registration surface.
    """
    try:
        from src.detection.cache_registration import register_detection_hooks

        register_detection_hooks()
        logger.debug("Registered detection plugin hooks")
    except ImportError:
        logger.debug("Detection plugin registration not available")
