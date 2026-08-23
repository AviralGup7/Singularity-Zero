"""Protocol registry for runtime binding of implementations.

This module provides a central registry where concrete implementations
can register themselves against the protocols defined in
cross_package_protocols.py. This allows decoupled packages to bind
implementations at startup time without circular imports.

Usage:
    # In the implementation package (e.g., src.fuzzing):
    from src.core.contracts.protocol_registry import register_ast_mutator
    register_ast_mutator(JSONASTMutator())

    # In the consumer package (e.g., src.core):
    from src.core.contracts.protocol_registry import get_ast_mutator
    mutator = get_ast_mutator()
    if mutator is not None:
        variants = mutator.mutate(decoded)
"""

from __future__ import annotations

import logging
from typing import Any

from src.core.contracts.cross_package_protocols import (
    ActiveManifestRegistryProtocol,
    AnalystNotesProtocol,
    ASTMutatorProtocol,
    AuthFlowRunnerProtocol,
    ChameleonEvasionProtocol,
    CorrectiveActionRegistryProtocol,
    ExploitReplayProtocol,
    FetchResponseProviderProtocol,
    IsolatedExecutionProtocol,
    LateralGraphProtocol,
    LauncherReplayManifestProtocol,
    OAuthAuthenticatorProtocol,
    RemediationScannerProtocol,
    RetryPolicyProtocol,
    SelfHealingControllerProtocol,
    TenantIsolationCheckProtocol,
    ValidationRuntimeProtocol,
    WASMExecutorProtocol,
)
from src.core.contracts.tool_execution import ToolExecutionServiceProtocol

logger = logging.getLogger(__name__)

# Track which missing registrations we've already warned about (to avoid log spam)
_warned_missing: set[str] = set()

# ---------------------------------------------------------------------------
# Private storage for registered implementations
# ---------------------------------------------------------------------------

_ast_mutator: ASTMutatorProtocol | None = None
_wasm_executor: WASMExecutorProtocol | None = None
_analysis_check_options: Any = None
_lateral_graph_cls: type[LateralGraphProtocol] | None = None
_fetch_response_provider: FetchResponseProviderProtocol | None = None
_response_comparator: Any = None
_plugin_artifact_loader: Any = None
_passive_check_names: Any = None
_chameleon_evasion: ChameleonEvasionProtocol | None = None
_exploit_replay: ExploitReplayProtocol | None = None
_remediation_scanner_cls: type[RemediationScannerProtocol] | None = None
_self_healing_controller_cls: type[SelfHealingControllerProtocol] | None = None
_corrective_action_registry_cls: type[CorrectiveActionRegistryProtocol] | None = None
_analyst_notes: AnalystNotesProtocol | None = None
_stage_baseline: Any = None
_active_manifest_registry: ActiveManifestRegistryProtocol | None = None
_validation_runtime: ValidationRuntimeProtocol | None = None
_isolated_execution: IsolatedExecutionProtocol | None = None
_oauth_authenticator_cls: type[OAuthAuthenticatorProtocol] | None = None
_auth_flow_runner_cls: type[AuthFlowRunnerProtocol] | None = None
_retry_policy_cls: type[RetryPolicyProtocol] | None = None
_launcher_manifest: LauncherReplayManifestProtocol | None = None
_tenant_isolation_check: TenantIsolationCheckProtocol | None = None
_tool_execution_service_cls: type[ToolExecutionServiceProtocol] | None = None


# ---------------------------------------------------------------------------
# Registration functions
# ---------------------------------------------------------------------------


def register_ast_mutator(mutator: ASTMutatorProtocol) -> None:
    """Register the AST mutator implementation."""
    global _ast_mutator
    _ast_mutator = mutator


def register_wasm_executor(executor: WASMExecutorProtocol) -> None:
    """Register the WASM executor implementation."""
    global _wasm_executor
    _wasm_executor = executor


def register_analysis_check_options(options: Any) -> None:
    """Register the analysis check options callable."""
    global _analysis_check_options
    _analysis_check_options = options


def register_lateral_graph_cls(cls: type[LateralGraphProtocol]) -> None:
    """Register the LateralGraph class."""
    global _lateral_graph_cls
    _lateral_graph_cls = cls


def register_fetch_response_provider(provider: FetchResponseProviderProtocol) -> None:
    """Register the fetch response provider."""
    global _fetch_response_provider
    _fetch_response_provider = provider


def register_response_comparator(comparator: Any) -> None:
    """Register the response comparator callable."""
    global _response_comparator
    _response_comparator = comparator


def register_plugin_artifact_loader(loader: Any) -> None:
    """Register the plugin artifact loader."""
    global _plugin_artifact_loader
    _plugin_artifact_loader = loader


def register_passive_check_names(names: Any) -> None:
    """Register the passive check names callable."""
    global _passive_check_names
    _passive_check_names = names


def register_chameleon_evasion(evasion: ChameleonEvasionProtocol) -> None:
    """Register the chameleon evasion callable."""
    global _chameleon_evasion
    _chameleon_evasion = evasion


def register_exploit_replay(replay: ExploitReplayProtocol) -> None:
    """Register the exploit replay callable."""
    global _exploit_replay
    _exploit_replay = replay


def register_remediation_scanner_cls(cls: type[RemediationScannerProtocol]) -> None:
    """Register the RemediationScanner class."""
    global _remediation_scanner_cls
    _remediation_scanner_cls = cls


def register_self_healing_controller_cls(cls: type[SelfHealingControllerProtocol]) -> None:
    """Register the SelfHealingController class."""
    global _self_healing_controller_cls
    _self_healing_controller_cls = cls


def register_corrective_action_registry_cls(cls: type[CorrectiveActionRegistryProtocol]) -> None:
    """Register the CorrectiveActionRegistry class."""
    global _corrective_action_registry_cls
    _corrective_action_registry_cls = cls


def register_analyst_notes(notes: AnalystNotesProtocol) -> None:
    """Register the analyst notes implementation."""
    global _analyst_notes
    _analyst_notes = notes


def register_stage_baseline(baseline: Any) -> None:
    """Register the stage baseline callable."""
    global _stage_baseline
    _stage_baseline = baseline


def register_active_manifest_registry(registry: ActiveManifestRegistryProtocol) -> None:
    """Register the active manifest registry."""
    global _active_manifest_registry
    _active_manifest_registry = registry


def register_validation_runtime(runtime: ValidationRuntimeProtocol) -> None:
    """Register the validation runtime callable."""
    global _validation_runtime
    _validation_runtime = runtime


def register_isolated_execution(execution: IsolatedExecutionProtocol) -> None:
    """Register the isolated execution callable."""
    global _isolated_execution
    _isolated_execution = execution


def register_oauth_authenticator_cls(cls: type[OAuthAuthenticatorProtocol]) -> None:
    """Register the OAuthAuthenticator class."""
    global _oauth_authenticator_cls
    _oauth_authenticator_cls = cls


def register_auth_flow_runner_cls(cls: type[AuthFlowRunnerProtocol]) -> None:
    """Register the AuthFlowRunner class."""
    global _auth_flow_runner_cls
    _auth_flow_runner_cls = cls


def register_retry_policy_cls(cls: type[RetryPolicyProtocol]) -> None:
    """Register the RetryPolicy class."""
    global _retry_policy_cls
    _retry_policy_cls = cls


def register_launcher_manifest(manifest: LauncherReplayManifestProtocol) -> None:
    """Register the launcher manifest implementation."""
    global _launcher_manifest
    _launcher_manifest = manifest


def register_tenant_isolation_check(check: TenantIsolationCheckProtocol) -> None:
    """Register the tenant isolation check callable."""
    global _tenant_isolation_check
    _tenant_isolation_check = check


def register_tool_execution_service_cls(cls: type[ToolExecutionServiceProtocol]) -> None:
    """Register the ToolExecutionService class."""
    global _tool_execution_service_cls
    _tool_execution_service_cls = cls


# ---------------------------------------------------------------------------
# Getter functions (return None if not registered)
# ---------------------------------------------------------------------------


def _warn_if_missing(name: str) -> None:
    """Log a warning once for a missing critical dependency registration."""
    if name not in _warned_missing:
        _warned_missing.add(name)
        logger.warning(
            "Protocol registry: '%s' is not registered. "
            "The feature requiring this dependency will be partially disabled.",
            name,
        )


def get_ast_mutator() -> ASTMutatorProtocol | None:
    """Get the registered AST mutator."""
    if _ast_mutator is None:
        _warn_if_missing("ast_mutator")
    return _ast_mutator


def get_wasm_executor() -> WASMExecutorProtocol | None:
    """Get the registered WASM executor."""
    if _wasm_executor is None:
        _warn_if_missing("wasm_executor")
    return _wasm_executor


def get_analysis_check_options() -> Any:
    """Get the registered analysis check options callable."""
    return _analysis_check_options


def get_lateral_graph_cls() -> type[LateralGraphProtocol] | None:
    """Get the registered LateralGraph class."""
    if _lateral_graph_cls is None:
        _warn_if_missing("lateral_graph_cls")
    return _lateral_graph_cls


def get_fetch_response_provider() -> FetchResponseProviderProtocol | None:
    """Get the registered fetch response provider."""
    return _fetch_response_provider


def get_response_comparator() -> Any:
    """Get the registered response comparator callable."""
    return _response_comparator


def get_plugin_artifact_loader() -> Any:
    """Get the registered plugin artifact loader."""
    return _plugin_artifact_loader


def get_passive_check_names() -> Any:
    """Get the registered passive check names callable."""
    return _passive_check_names


def get_chameleon_evasion() -> ChameleonEvasionProtocol | None:
    """Get the registered chameleon evasion callable."""
    return _chameleon_evasion


def get_exploit_replay() -> ExploitReplayProtocol | None:
    """Get the registered exploit replay callable."""
    return _exploit_replay


def get_remediation_scanner_cls() -> type[RemediationScannerProtocol] | None:
    """Get the registered RemediationScanner class."""
    if _remediation_scanner_cls is None:
        _warn_if_missing("remediation_scanner_cls")
    return _remediation_scanner_cls


def get_self_healing_controller_cls() -> type[SelfHealingControllerProtocol] | None:
    """Get the registered SelfHealingController class."""
    if _self_healing_controller_cls is None:
        _warn_if_missing("self_healing_controller_cls")
    return _self_healing_controller_cls


def get_corrective_action_registry_cls() -> type[CorrectiveActionRegistryProtocol] | None:
    """Get the registered CorrectiveActionRegistry class."""
    if _corrective_action_registry_cls is None:
        _warn_if_missing("corrective_action_registry_cls")
    return _corrective_action_registry_cls


def get_analyst_notes() -> AnalystNotesProtocol | None:
    """Get the registered analyst notes implementation."""
    return _analyst_notes


def get_stage_baseline() -> Any:
    """Get the registered stage baseline callable."""
    return _stage_baseline


def get_active_manifest_registry() -> ActiveManifestRegistryProtocol | None:
    """Get the registered active manifest registry."""
    return _active_manifest_registry


def get_validation_runtime() -> ValidationRuntimeProtocol | None:
    """Get the registered validation runtime callable."""
    if _validation_runtime is None:
        _warn_if_missing("validation_runtime")
    return _validation_runtime


def get_isolated_execution() -> IsolatedExecutionProtocol | None:
    """Get the registered isolated execution callable."""
    if _isolated_execution is None:
        _warn_if_missing("isolated_execution")
    return _isolated_execution


def get_oauth_authenticator_cls() -> type[OAuthAuthenticatorProtocol] | None:
    """Get the registered OAuthAuthenticator class."""
    if _oauth_authenticator_cls is None:
        _warn_if_missing("oauth_authenticator_cls")
    return _oauth_authenticator_cls


def get_auth_flow_runner_cls() -> type[AuthFlowRunnerProtocol] | None:
    """Get the registered AuthFlowRunner class."""
    if _auth_flow_runner_cls is None:
        _warn_if_missing("auth_flow_runner_cls")
    return _auth_flow_runner_cls


def get_retry_policy_cls() -> type[RetryPolicyProtocol] | None:
    """Get the registered RetryPolicy class."""
    return _retry_policy_cls


def get_launcher_manifest() -> LauncherReplayManifestProtocol | None:
    """Get the registered launcher manifest implementation."""
    return _launcher_manifest


def get_tenant_isolation_check() -> TenantIsolationCheckProtocol | None:
    """Get the registered tenant isolation check callable."""
    if _tenant_isolation_check is None:
        _warn_if_missing("tenant_isolation_check")
    return _tenant_isolation_check


def get_tool_execution_service_cls() -> type[ToolExecutionServiceProtocol] | None:
    """Get the registered ToolExecutionService class."""
    if _tool_execution_service_cls is None:
        _warn_if_missing("tool_execution_service_cls")
    return _tool_execution_service_cls


def reset_protocol_registry() -> None:
    """Clear every registered binding (process reload and tests)."""
    global _ast_mutator, _wasm_executor, _analysis_check_options
    global _lateral_graph_cls, _fetch_response_provider, _response_comparator
    global _plugin_artifact_loader, _passive_check_names, _chameleon_evasion
    global _exploit_replay, _remediation_scanner_cls
    global _self_healing_controller_cls, _corrective_action_registry_cls
    global _analyst_notes, _stage_baseline, _active_manifest_registry
    global _validation_runtime, _isolated_execution, _oauth_authenticator_cls
    global _auth_flow_runner_cls, _retry_policy_cls, _launcher_manifest
    global _tenant_isolation_check, _tool_execution_service_cls
    _ast_mutator = None
    _wasm_executor = None
    _analysis_check_options = None
    _lateral_graph_cls = None
    _fetch_response_provider = None
    _response_comparator = None
    _plugin_artifact_loader = None
    _passive_check_names = None
    _chameleon_evasion = None
    _exploit_replay = None
    _remediation_scanner_cls = None
    _self_healing_controller_cls = None
    _corrective_action_registry_cls = None
    _analyst_notes = None
    _stage_baseline = None
    _active_manifest_registry = None
    _validation_runtime = None
    _isolated_execution = None
    _oauth_authenticator_cls = None
    _auth_flow_runner_cls = None
    _retry_policy_cls = None
    _launcher_manifest = None
    _tenant_isolation_check = None
    _tool_execution_service_cls = None
    _warned_missing.clear()
