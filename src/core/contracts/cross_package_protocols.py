"""Cross-package protocols for decoupling architectural layers.

This module defines Protocol interfaces that allow higher-layer packages
to depend on abstractions rather than concrete implementations from other
packages. This is the primary mechanism for enforcing the import-linter
contracts while maintaining runtime functionality.

Usage:
    - Dashboard imports protocols from this module instead of from analysis/execution/pipeline
    - Pipeline imports protocols from this module instead of from execution
    - Core imports protocols from this module instead of from fuzzing
    - Infrastructure imports protocols from this module instead of from pipeline
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

# ---------------------------------------------------------------------------
# Core → Fuzzing protocol (fixes Contract 4/18)
# ---------------------------------------------------------------------------


@runtime_checkable
class ASTMutatorProtocol(Protocol):
    """Protocol for AST-based JSON mutation engines.

    Implemented by: src.fuzzing.ast_mutator.JSONASTMutator
    Used by: src.core.mutation_engine
    """

    def mutate(self, decoded: Any) -> list[Any]:
        """Return a list of mutated JSON values from the decoded input."""
        ...


# ---------------------------------------------------------------------------
# Analysis → Execution protocol (fixes Contract 8/15)
# ---------------------------------------------------------------------------


@runtime_checkable
class WASMExecutorProtocol(Protocol):
    """Protocol for WASM sandbox execution.

    Implemented by: src.execution.frontier.wasm.execute_sandboxed_plugin
    Used by: src.analysis.plugins.wasm
    """

    def execute_sandboxed_plugin(
        self,
        wasm_path: str,
        stage_input: dict[str, Any],
        *,
        timeout_seconds: float | None = None,
    ) -> dict[str, Any]:
        """Execute a WASM plugin in a sandboxed environment."""
        ...


# ---------------------------------------------------------------------------
# Dashboard → Analysis protocols (fixes Contract 11)
# ---------------------------------------------------------------------------


@runtime_checkable
class AnalysisCheckOptionsProtocol(Protocol):
    """Protocol for analysis check options registry.

    Implemented by: src.analysis.plugins.analysis_check_options
    Used by: src.dashboard.constants.analysis, src.dashboard.fastapi.routers.registry
    """

    def __call__(self) -> dict[str, Any]:
        """Return the analysis check options."""
        ...


@runtime_checkable
class LateralGraphProtocol(Protocol):
    """Protocol for lateral movement graph analysis.

    Implemented by: src.analysis.intelligence.lateral_graph.LateralGraph
    Used by: src.dashboard.fastapi.routers.cockpit.chains
    """

    def __init__(self, db_path: str) -> None: ...

    def find_attack_chains(self) -> list[dict[str, Any]]:
        """Return identified attack chains."""
        ...


@runtime_checkable
class FetchResponseProviderProtocol(Protocol):
    """Protocol for providing cached fetch responses.

    Implemented by: src.analysis.passive.runtime._get_fetch_response
    Used by: src.dashboard.fastapi.routers.cockpit.notes, src.dashboard.fastapi.routers.replay
    """

    def __call__(self) -> Any:
        """Return the current fetch response."""
        ...


@runtime_checkable
class ResponseComparatorProtocol(Protocol):
    """Protocol for comparing HTTP response records.

    Implemented by: src.analysis.behavior.analysis_support.compare_response_records
    Used by: src.dashboard.fastapi.routers.replay
    """

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        """Compare response records."""
        ...


@runtime_checkable
class PluginArtifactLoaderProtocol(Protocol):
    """Protocol for loading plugin artifacts.

    Implemented by: src.analysis.behavior.artifacts
    Used by: src.dashboard.fastapi.routers.replay
    """

    def load_plugin_artifact(self, *args: Any, **kwargs: Any) -> Any:
        """Load a plugin artifact."""
        ...

    def plugin_artifact_path(self, *args: Any, **kwargs: Any) -> Any:
        """Return the path to a plugin artifact."""
        ...


@runtime_checkable
class PassiveCheckNamesProtocol(Protocol):
    """Protocol for passive check name registry.

    Implemented by: src.analysis.plugins.PASSIVE_CHECK_NAMES
    Used by: src.dashboard.configuration
    """

    def __call__(self) -> list[str]:
        """Return the list of passive check names."""
        ...


# ---------------------------------------------------------------------------
# Dashboard → Execution protocols (fixes Contract 12)
# ---------------------------------------------------------------------------


@runtime_checkable
class ChameleonEvasionProtocol(Protocol):
    """Protocol for chameleon evasion strategy.

    Implemented by: src.execution.frontier.chameleon._chameleon
    Used by: src.dashboard.fastapi.routers.evasion
    """

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        """Apply chameleon evasion strategy."""
        ...


@runtime_checkable
class ExploitReplayProtocol(Protocol):
    """Protocol for replaying exploit headers.

    Implemented by: src.execution.exploiters.exploit_automation.replay_headers_for_mode
    Used by: src.dashboard.fastapi.routers.replay
    """

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        """Replay headers for the specified mode."""
        ...


@runtime_checkable
class RemediationScannerProtocol(Protocol):
    """Protocol for remediation scanning.

    Implemented by: src.execution.remediators.remediation_scanner.RemediationScanner
    Used by: src.dashboard.fastapi.routers.remediated
    """

    def verify_remediation(
        self,
        finding: dict[str, Any],
        redis_client: Any = None,
        tenant_id: str | None = None,
    ) -> dict[str, Any]:
        """Verify if a finding has been successfully remediated."""
        ...


# ---------------------------------------------------------------------------
# Dashboard → Pipeline protocols (fixes Contract 13)
# ---------------------------------------------------------------------------


@runtime_checkable
class SelfHealingControllerProtocol(Protocol):
    """Protocol for self-healing controller.

    Implemented by: src.pipeline.self_healing.SelfHealingController
    Used by: src.dashboard.fastapi.self_healing_setup, src.infrastructure.observability.health_subscriber
    """

    def __init__(self, action_registry: Any) -> None: ...

    def subscribe_event_bus(self, event_bus: Any) -> str:
        """Subscribe to the event bus and return subscription ID."""
        ...

    @property
    def _event_bus(self) -> Any:
        """Return the event bus."""
        ...

    @_event_bus.setter
    def _event_bus(self, value: Any) -> None:
        """Set the event bus."""
        ...


@runtime_checkable
class CorrectiveActionRegistryProtocol(Protocol):
    """Protocol for corrective action registry.

    Implemented by: src.pipeline.self_healing.CorrectiveActionRegistry
    Used by: src.dashboard.fastapi.self_healing_setup
    """

    def register(self, action: Any, handler: Any) -> None:
        """Register a corrective action handler."""
        ...


@runtime_checkable
class AnalystNotesProtocol(Protocol):
    """Protocol for analyst notes operations.

    Implemented by: src.pipeline.analyst_notes
    Used by: src.dashboard.fastapi.routers.notes, src.dashboard.fastapi.routers.cockpit.notes
    """

    def get_all_notes(self, target_name: str, output_dir: str = "") -> list[Any]:
        """Return all notes for a target."""
        ...

    def create_note(
        self,
        target_name: str,
        finding_id: str,
        note: str = "",
        tags: list[str] | None = None,
        graph_node_id: str | None = None,
        graph_edge_id: str | None = None,
        exchange_id: str | None = None,
        output_dir: str = "",
    ) -> Any:
        """Create a new analyst note."""
        ...

    def update_note(
        self,
        target_name: str,
        finding_id: str,
        note_id: str,
        note: str = "",
        tags: list[str] | None = None,
        graph_node_id: str | None = None,
        graph_edge_id: str | None = None,
        exchange_id: str | None = None,
        output_dir: str = "",
    ) -> Any:
        """Update an existing note."""
        ...

    def delete_note(
        self,
        target_name: str,
        note_id: str,
        finding_id: str,
        output_dir: str = "",
    ) -> bool:
        """Delete a note."""
        ...


@runtime_checkable
class StageBaselineProtocol(Protocol):
    """Protocol for stage baseline progress constants.

    Implemented by: src.pipeline.constants.progress.STAGE_BASELINE_PERCENT
    Used by: src.dashboard.job_state_helpers, src.dashboard.progress_ingestion
    """

    def __call__(self, stage: str) -> int:
        """Return the baseline percentage for a stage."""
        ...


# ---------------------------------------------------------------------------
# Pipeline → Execution protocols (fixes Contract 14)
# ---------------------------------------------------------------------------


@runtime_checkable
class ActiveManifestRegistryProtocol(Protocol):
    """Protocol for active manifest registry.

    Implemented by: src.execution.active_manifest.DEFAULT_ACTIVE_MANIFEST_REGISTRY
    Used by: src.pipeline.services.pipeline_orchestrator.stages.probe_registry
    """

    def get(self, check_id: str) -> Any | None:
        """Return the manifest entry for a check ID."""
        ...


@runtime_checkable
class ValidationRuntimeProtocol(Protocol):
    """Protocol for validation runtime execution.

    Implemented by: src.execution.validators.execute_validation_runtime
    Used by: src.pipeline.services.pipeline_orchestrator.stages.analysis, validation
    """

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        """Execute the validation runtime."""
        ...


@runtime_checkable
class IsolatedExecutionProtocol(Protocol):
    """Protocol for isolated callable execution.

    Implemented by: src.execution.isolated.run_callable_isolated
    Used by: src.pipeline.services.pipeline_orchestrator.stages.probe_runners
    """

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        """Run a callable in isolation."""
        ...


@runtime_checkable
class OAuthAuthenticatorProtocol(Protocol):
    """Protocol for OAuth authentication.

    Implemented by: src.execution.auth.OAuthAuthenticator
    Used by: src.pipeline.services.pipeline_orchestrator.stages.session_provisioning
    """

    async def authenticate(self) -> Any:
        """Perform OAuth authentication and return session context."""
        ...


@runtime_checkable
class AuthFlowRunnerProtocol(Protocol):
    """Protocol for multi-step auth flow execution.

    Implemented by: src.execution.auth.AuthFlowRunner
    Used by: src.pipeline.services.pipeline_orchestrator.stages.session_provisioning
    """

    async def run(self, auth_spec: Any) -> Any:
        """Run the auth flow and return session context."""
        ...


# ---------------------------------------------------------------------------
# Execution → Pipeline protocols (fixes Contract 16)
# ---------------------------------------------------------------------------


@runtime_checkable
class RetryPolicyProtocol(Protocol):
    """Protocol for retry policies.

    Implemented by: src.pipeline.retry.RetryPolicy
    Used by: src.execution.validators.engine._runner, _http_client, registry_builder
    """

    @property
    def max_attempts(self) -> int:
        """Return the maximum number of retry attempts."""
        ...

    @property
    def initial_backoff_seconds(self) -> float:
        """Return the initial backoff duration in seconds."""
        ...


# ---------------------------------------------------------------------------
# Infrastructure → Pipeline protocols (fixes Contract 17)
# ---------------------------------------------------------------------------

# SelfHealingControllerProtocol is defined above (Dashboard → Pipeline section)
# and is reused here for infrastructure dependency.

# ---------------------------------------------------------------------------
# Pipeline → Dashboard protocols (fixes Unlisted violation)
# ---------------------------------------------------------------------------


@runtime_checkable
class LauncherReplayManifestProtocol(Protocol):
    """Protocol for launcher replay manifest operations.

    Implemented by: src.dashboard.forensics.launcher
    Used by: src.pipeline.runtime, src.pipeline.services.job_artifact_packager
    """

    def build_launcher_replay_manifest(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        """Build a launcher replay manifest."""
        ...

    def compare_launcher_replay_manifests(
        self, baseline: dict[str, Any], new_run: dict[str, Any]
    ) -> dict[str, Any]:
        """Compare two launcher replay manifests."""
        ...


# ---------------------------------------------------------------------------
# Execution → Dashboard protocols (fixes Unlisted violation)
# ---------------------------------------------------------------------------


@runtime_checkable
class TenantIsolationCheckProtocol(Protocol):
    """Protocol for tenant isolation checks.

    Implemented by: src.dashboard.fastapi.routers.targets.is_target_owned_by_tenant
    Used by: src.execution.remediators.remediation_scanner
    """

    def __call__(self, target_name: str, tenant_id: str) -> bool:
        """Return True if the target is owned by the specified tenant."""
        ...
