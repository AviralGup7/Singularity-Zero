"""Formal schema registry for pipeline state_delta keys.

Ensures that data merged into the global PipelineContext from stages
adheres to defined keys and types, preventing state poisoning.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TypeVar

T = TypeVar("T")


@dataclass(frozen=True, slots=True)
class StateSchema:
    """Definition of a valid state_delta entry."""

    key: str
    expected_type: type[Any] | tuple[type[Any], ...]
    description: str = ""
    required: bool = False


class StateSchemaRegistry:
    """Registry of allowed state_delta keys and their types."""

    def __init__(self) -> None:
        self._schemas: dict[str, StateSchema] = {}

    def register(self, schema: StateSchema) -> None:
        """Register a new allowed state key."""
        self._schemas[schema.key] = schema

    def validate_delta(self, delta: Mapping[str, Any]) -> list[str]:
        """Validate a state_delta against registered schemas.

        Returns a list of error messages, or an empty list if valid.
        """
        errors: list[str] = []
        for key, value in delta.items():
            schema = self._schemas.get(key)
            if not schema:
                errors.append(f"Unregistered state_delta key: '{key}'")
                continue

            if not _matches_expected_type(value, schema.expected_type):
                expected_name = (
                    schema.expected_type.__name__
                    if isinstance(schema.expected_type, type)
                    else str(schema.expected_type)
                )
                actual_name = type(value).__name__
                errors.append(
                    f"Type mismatch for key '{key}': expected {expected_name}, got {actual_name}"
                )

        # Check for missing required keys
        # Note: state_delta is incremental, so 'required' usually applies to the final merged state,
        # but here we can use it to enforce that a stage MUST produce certain keys if it's the owner.
        # For now, we'll keep it simple and only validate what is actually present in the delta.

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


# Global registry instance
GLOBAL_STATE_SCHEMA_REGISTRY = StateSchemaRegistry()


def register_state_schema(
    key: str, expected_type: type[Any] | tuple[type[Any], ...], description: str = ""
) -> None:
    """Helper to register a state schema entry."""
    GLOBAL_STATE_SCHEMA_REGISTRY.register(
        StateSchema(key=key, expected_type=expected_type, description=description)
    )


# Initial core schema registrations
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
