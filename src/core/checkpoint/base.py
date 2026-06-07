"""Core checkpoint state and serialization primitives."""

from __future__ import annotations

import hashlib
import time
from dataclasses import asdict, dataclass, field
from typing import Any, cast


class CheckpointIntegrityError(ValueError):
    """Raised when checkpoint checksum validation fails."""


@dataclass
class CheckpointState:
    """Serializable snapshot of pipeline execution state."""

    pipeline_run_id: str
    """Unique identifier for this pipeline run."""

    checkpoint_version: int = 1
    """Incremented on each checkpoint."""

    schema_version: int = 2
    """Checkpoint schema structure version."""

    completed_stages: list[str] = field(default_factory=list)
    """Stage names that completed successfully."""

    current_stage: str | None = None
    """Stage currently executing (None if not started or finished)."""

    stage_results: dict[str, dict[str, Any]] = field(default_factory=dict)
    """Per-stage serialized results."""

    module_metrics: dict[str, Any] = field(default_factory=dict)
    """Timing and status metrics."""

    started_at: float = field(default_factory=time.time)
    """Unix timestamp when the pipeline run started."""

    last_checkpoint_at: float = field(default_factory=time.time)
    """Unix timestamp of the last checkpoint save."""

    crash_recovery: bool = False
    """Whether this is a recovery run."""

    recovery_from: str | None = None
    """Run ID we're recovering from."""

    iterative_state: dict[str, Any] = field(default_factory=dict)
    """State for iterative analysis (finding keys, feedback URLs, etc.)."""

    nuclei_state: dict[str, Any] = field(default_factory=dict)
    """Nuclei scanning state (targets, findings, etc.)."""

    stage_deltas: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    """Incremental per-stage progress deltas for mid-stage resume."""

    scanned_assets: list[str] = field(default_factory=list)
    """Asset inventory snapshot from the most recent monitoring cycle."""

    previous_findings: list[dict[str, Any]] = field(default_factory=list)
    """Findings from the previous monitoring cycle for diff/alerting."""

    def to_dict(self) -> dict[str, Any]:
        """Convert state to a JSON-serializable dictionary."""
        raw = asdict(self)
        return cast(dict[str, Any], _serialize_sets(raw))

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CheckpointState:
        """Reconstruct a CheckpointState from a deserialized dictionary."""
        import dataclasses

        from src.core.checkpoint.migrations import GLOBAL_MIGRATION_REGISTRY

        data.pop("checksum", None)
        migrated = GLOBAL_MIGRATION_REGISTRY.migrate(data)

        # Keep only fields present in CheckpointState dataclass for robustness/forward-compatibility
        valid_fields = {f.name for f in dataclasses.fields(cls)}
        filtered = {k: v for k, v in migrated.items() if k in valid_fields}

        restored = _deserialize_sets(filtered)
        return cls(**restored)



def _serialize_sets(obj: Any) -> Any:
    """Recursively convert sets to sorted lists for JSON serialization."""
    if isinstance(obj, set):
        return sorted(str(item) for item in obj)
    if isinstance(obj, dict):
        return {key: _serialize_sets(value) for key, value in obj.items()}
    if isinstance(obj, list):
        return [_serialize_sets(item) for item in obj]
    return obj


def _deserialize_sets(obj: Any) -> Any:
    """Recursively restore sets from lists for known set-field keys."""
    if isinstance(obj, dict):
        result = {}
        for key, value in obj.items():
            if key in {"completed_stages", "scanned_assets"} and isinstance(value, list):
                result[key] = set(value)
            else:
                result[key] = _deserialize_sets(value)
        return result
    if isinstance(obj, list):
        return [_deserialize_sets(item) for item in obj]
    return obj


def _compute_checksum(data: str) -> str:
    """Compute a SHA-256 checksum for the given string data."""
    return hashlib.sha256(data.encode("utf-8")).hexdigest()
