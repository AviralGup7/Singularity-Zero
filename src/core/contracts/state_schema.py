"""Formal schema registry for pipeline state_delta keys.

Ensures that data merged into the global PipelineContext from stages
adheres to defined keys and types, preventing state poisoning.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, TypeVar

T = TypeVar("T")

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class StateSchema:
    """Definition of a valid state_delta entry."""

    key: str
    expected_type: type[Any] | tuple[type[Any], ...]
    description: str = ""
    required: bool = False


class Mode(Enum):
    """Validation mode for the state schema registry.

    STRICT — raise SchemaValidationError on unregistered keys (default).
    WARN   — log a warning but allow unregistered keys through.
    OFF    — skip validation entirely.
    """

    STRICT = "strict"
    WARN = "warn"
    OFF = "off"


class StateSchemaRegistry:
    """Registry of allowed state_delta keys and their types."""

    def __init__(
        self, *, mode: Mode = Mode.STRICT, validate_on_merge: bool = True
    ) -> None:
        self._schemas: dict[str, StateSchema] = {}
        self._mode = mode
        self.validate_on_merge = validate_on_merge

    @property
    def mode(self) -> Mode:
        """Current validation mode."""
        return self._mode

    @mode.setter
    def mode(self, value: Mode) -> None:
        self._mode = value

    def register(self, schema: StateSchema) -> None:
        """Register a new allowed state key."""
        self._schemas[schema.key] = schema

    def validate_delta(self, delta: Mapping[str, Any]) -> list[str]:
        """Validate a state_delta against registered schemas.

        Returns a list of error messages, or an empty list if valid.
        Respects the current mode:
          - STRICT: returns errors (caller raises).
          - WARN:  logs warnings, returns errors for informational use.
          - OFF:   returns empty list immediately.
        """
        if self._mode == Mode.OFF:
            return []

        errors: list[str] = []
        for key, value in delta.items():
            schema = self._schemas.get(key)
            if not schema:
                msg = f"Unregistered state_delta key: '{key}'"
                if self._mode == Mode.WARN:
                    logger.warning(msg)
                else:
                    errors.append(msg)
                continue

            if not _matches_expected_type(value, schema.expected_type):
                expected_name = (
                    schema.expected_type.__name__
                    if isinstance(schema.expected_type, type)
                    else str(schema.expected_type)
                )
                actual_name = type(value).__name__
                type_msg = (
                    f"Type mismatch for key '{key}': expected {expected_name}, got {actual_name}"
                )
                if self._mode == Mode.WARN:
                    logger.warning(type_msg)
                else:
                    errors.append(type_msg)

        return errors


def _matches_expected_type(value: Any, expected_type: type[Any] | tuple[type[Any], ...]) -> bool:
    """Return whether a frozen or mutable stage value matches its schema type."""
    if isinstance(value, expected_type):
        return True

    expected_types = expected_type if isinstance(expected_type, tuple) else (expected_type,)
    if set in expected_types and isinstance(value, frozenset):
        return True
    if dict in expected_types and isinstance(value, Mapping):
        return True
    if list in expected_types and isinstance(value, tuple):
        return True
    if Path in expected_types and isinstance(value, str):
        return True
    return False


def _resolve_mode_from_env() -> Mode:
    """Read PIPELINE_STATE_MODE env var and return the corresponding Mode."""
    raw = os.environ.get("PIPELINE_STATE_MODE", "").strip().lower()
    if raw in {"off"}:
        return Mode.OFF
    if raw in {"warn"}:
        return Mode.WARN
    # strict is the default for any unrecognised or missing value
    return Mode.STRICT


def _is_dev_mode() -> bool:
    """Return True when running in a development environment."""
    return os.environ.get("PYTHON_ENV", "").strip().lower() in {
        "development",
        "dev",
    }


# Global registry instance — mode is configured from PIPELINE_STATE_MODE env var.
# In dev mode, validation is automatically downgraded from STRICT to WARN.
_env_mode = _resolve_mode_from_env()
_dev_mode = _is_dev_mode()
if _dev_mode and _env_mode == Mode.STRICT:
    _effective_mode = Mode.WARN
else:
    _effective_mode = _env_mode

GLOBAL_STATE_SCHEMA_REGISTRY = StateSchemaRegistry(mode=_effective_mode)


def register_state_schema(
    key: str, expected_type: type[Any] | tuple[type[Any], ...], description: str = ""
) -> None:
    """Helper to register a state schema entry."""
    GLOBAL_STATE_SCHEMA_REGISTRY.register(
        StateSchema(key=key, expected_type=expected_type, description=description)
    )


# Initial core schema registrations
# NOTE: "_neural_state" CRDT registration removed — the NeuralState container is
# managed internally by StageResult / MeshShim and must not leak into the
# pipeline state_delta.
register_state_schema("scope_entries", (list, tuple), "Original target scope entries")
register_state_schema("use_cache", bool, "Whether result caching is enabled")
register_state_schema("module_metrics", dict, "Per-stage metrics and status info")
register_state_schema("previous_run", (Path, str), "Previous run directory for trend analysis")
register_state_schema("tool_status", dict, "Tool availability status")
register_state_schema("flow_manifest", dict, "Pipeline flow manifest")
register_state_schema("started_at", (int, float), "Pipeline start timestamp")
register_state_schema("discovery_enabled", bool, "Whether discovery tools are enabled")
register_state_schema("subdomains", (set, frozenset, list, tuple), "Discovered subdomain set")
register_state_schema(
    "live_hosts", (set, frozenset, list, tuple), "Discovered live HTTP service URLs"
)
register_state_schema(
    "live_records", (list, tuple), "Detailed HTTP response records for live hosts"
)
register_state_schema("service_results", dict, "Service enrichment results keyed by host")
register_state_schema("urls", (set, list, tuple), "Collected URL set")
register_state_schema("url_stage_meta", dict, "Metadata about URL collection")
register_state_schema("parameters", (set, list, tuple), "Extracted query/post parameters")
register_state_schema("ranked_priority_urls", (list, tuple), "Scored and ranked URL objects")
register_state_schema("priority_urls", (list, tuple), "High-priority URL strings")
register_state_schema("selected_priority_items", (list, tuple), "Items selected for deep analysis")
register_state_schema("selection_meta", dict, "Metadata about deep analysis selection")
register_state_schema("deep_analysis_urls", (list, tuple), "Final deep analysis target URLs")
register_state_schema("target_profile", dict, "Inferred profile of the target application")
register_state_schema("history_feedback", dict, "Learning feedback from previous runs")
register_state_schema("analysis_results", dict, "Per-module analysis results")
register_state_schema("validation_runtime_inputs", dict, "Inputs prepared for validation")
register_state_schema("validation_summary", dict, "Summary of validation execution")
register_state_schema("campaign_summary", dict, "Simulated attack campaign summary")
register_state_schema("merged_findings", (list, tuple), "Merged security findings")
register_state_schema("reportable_findings", (list, tuple), "High-confidence report findings")
register_state_schema("iterative_stop_reason", str, "Reason the iterative loop terminated")
register_state_schema("executed_iterations", int, "Number of analysis iterations executed")
register_state_schema("passive_scan_ok", bool, "Whether passive scanning completed")
register_state_schema("validation_ok", bool, "Whether validation completed")
register_state_schema("screenshots", (list, tuple), "Screenshot result records")
register_state_schema("diff_summary", dict, "Artifact diff summary")
register_state_schema("nuclei_findings", (list, tuple), "Parsed Nuclei findings")
register_state_schema("stage_status", dict, "Per-stage execution status")
register_state_schema("findings", (list, tuple), "Legacy security findings list")
register_state_schema("vulnerabilities", (list, tuple), "Validated vulnerability records")
register_state_schema("artifacts_meta", dict, "Metadata about persisted stage artifacts")
register_state_schema("_wal_id", (int, str), "Write-ahead log ID for stage delta replay")
register_state_schema("threat_graph", dict, "Threat graph structure representing attack vectors")
register_state_schema("threat_graph_summary", dict, "Summary of the threat graph metrics")
