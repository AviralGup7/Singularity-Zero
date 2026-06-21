"""Startup registration of protocol implementations.

This module registers all concrete implementations against the protocols
defined in cross_package_protocols.py. It should be called once during
application startup (e.g., from the FastAPI lifespan or CLI entry point).

This module is the ONLY place where cross-package imports are allowed
for registration purposes. It acts as the composition root.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

_REGISTERED = False


def register_all_implementations() -> None:
    """Register all protocol implementations at startup.

    This function is idempotent — calling it multiple times is safe.
    """
    global _REGISTERED
    if _REGISTERED:
        return

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
        register_validation_runtime,
        register_wasm_executor,
    )

    # Core → Fuzzing (Contract 4/18)
    try:
        from src.fuzzing.ast_mutator import JSONASTMutator

        register_ast_mutator(JSONASTMutator())
        logger.debug("Registered ASTMutator (fuzzing)")
    except ImportError:
        logger.debug("JSONASTMutator not available")

    # Analysis → Execution (Contract 8/15)
    try:
        from src.execution.frontier.wasm import execute_sandboxed_plugin

        register_wasm_executor(execute_sandboxed_plugin)
        logger.debug("Registered WASM executor (execution.frontier.wasm)")
    except ImportError:
        logger.debug("WASM executor not available")

    # Dashboard → Analysis (Contract 11)
    try:
        from src.analysis.plugins import PASSIVE_CHECK_NAMES, analysis_check_options

        register_analysis_check_options(analysis_check_options)
        register_passive_check_names(PASSIVE_CHECK_NAMES)
        logger.debug("Registered analysis check options and passive check names")
    except ImportError:
        logger.debug("Analysis plugins not available")

    try:
        from src.analysis.intelligence.lateral_graph import LateralGraph

        register_lateral_graph_cls(LateralGraph)
        logger.debug("Registered LateralGraph")
    except ImportError:
        logger.debug("LateralGraph not available")

    try:
        from src.analysis.passive.runtime import _get_fetch_response

        register_fetch_response_provider(_get_fetch_response)
        logger.debug("Registered fetch response provider")
    except ImportError:
        logger.debug("Fetch response provider not available")

    try:
        from src.analysis.behavior.analysis_support import compare_response_records

        register_response_comparator(compare_response_records)
        logger.debug("Registered response comparator")
    except ImportError:
        logger.debug("Response comparator not available")

    try:
        from src.analysis.behavior import artifacts as _artifacts

        register_plugin_artifact_loader(_artifacts)
        logger.debug("Registered plugin artifact loader")
    except ImportError:
        logger.debug("Plugin artifact loader not available")

    # Dashboard → Execution (Contract 12)
    try:
        from src.execution.frontier.chameleon import _chameleon

        register_chameleon_evasion(_chameleon)
        logger.debug("Registered chameleon evasion")
    except ImportError:
        logger.debug("Chameleon evasion not available")

    try:
        from src.execution.exploiters.exploit_automation import replay_headers_for_mode

        register_exploit_replay(replay_headers_for_mode)
        logger.debug("Registered exploit replay")
    except ImportError:
        logger.debug("Exploit replay not available")

    try:
        from src.execution.remediators.remediation_scanner import RemediationScanner

        register_remediation_scanner_cls(RemediationScanner)
        logger.debug("Registered RemediationScanner")
    except ImportError:
        logger.debug("RemediationScanner not available")

    # Dashboard → Pipeline (Contract 13)
    try:
        from src.pipeline.self_healing import (
            CorrectiveActionRegistry,
            SelfHealingController,
        )

        register_self_healing_controller_cls(SelfHealingController)
        register_corrective_action_registry_cls(CorrectiveActionRegistry)
        logger.debug("Registered SelfHealingController and CorrectiveActionRegistry")
    except ImportError:
        logger.debug("Self-healing not available")

    try:
        from src.pipeline import analyst_notes as _notes

        register_analyst_notes(_notes)
        logger.debug("Registered analyst notes")
    except ImportError:
        logger.debug("Analyst notes not available")

    try:
        from src.pipeline.constants.progress import STAGE_BASELINE_PERCENT

        register_stage_baseline(STAGE_BASELINE_PERCENT)
        logger.debug("Registered stage baseline")
    except ImportError:
        logger.debug("Stage baseline not available")

    # Pipeline → Execution (Contract 14)
    try:
        from src.execution.active_manifest import DEFAULT_ACTIVE_MANIFEST_REGISTRY

        register_active_manifest_registry(DEFAULT_ACTIVE_MANIFEST_REGISTRY)
        logger.debug("Registered active manifest registry")
    except ImportError:
        logger.debug("Active manifest registry not available")

    try:
        from src.execution.validators import execute_validation_runtime

        register_validation_runtime(execute_validation_runtime)
        logger.debug("Registered validation runtime")
    except ImportError:
        logger.debug("Validation runtime not available")

    try:
        from src.execution.isolated import run_callable_isolated

        register_isolated_execution(run_callable_isolated)
        logger.debug("Registered isolated execution")
    except ImportError:
        logger.debug("Isolated execution not available")

    try:
        from src.execution.auth import AuthFlowRunner, OAuthAuthenticator

        register_oauth_authenticator_cls(OAuthAuthenticator)
        register_auth_flow_runner_cls(AuthFlowRunner)
        logger.debug("Registered OAuth authenticator and auth flow runner")
    except ImportError:
        logger.debug("Auth modules not available")

    # Execution → Pipeline (Contract 16)
    try:
        from src.pipeline.retry import RetryPolicy

        register_retry_policy_cls(RetryPolicy)
        logger.debug("Registered RetryPolicy")
    except ImportError:
        logger.debug("RetryPolicy not available")

    # Pipeline → Dashboard (Unlisted)
    try:
        from src.dashboard.forensics.launcher import (
            build_launcher_replay_manifest,
            compare_launcher_replay_manifests,
        )

        class _LauncherManifest:
            def build_launcher_replay_manifest(self, *args: Any, **kwargs: Any) -> Any:
                return build_launcher_replay_manifest(*args, **kwargs)

            def compare_launcher_replay_manifests(self, baseline: Any, new_run: Any) -> Any:
                return compare_launcher_replay_manifests(baseline, new_run)

        register_launcher_manifest(_LauncherManifest())
        logger.debug("Registered launcher manifest")
    except ImportError:
        logger.debug("Launcher manifest not available")

    # Execution → Dashboard (Unlisted)
    try:
        from src.dashboard.fastapi.routers.targets import is_target_owned_by_tenant

        register_tenant_isolation_check(is_target_owned_by_tenant)
        logger.debug("Registered tenant isolation check")
    except ImportError:
        logger.debug("Tenant isolation check not available")

    _REGISTERED = True
    logger.info("All protocol implementations registered")
