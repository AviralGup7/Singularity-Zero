"""Checkpoint schema migration registry and migrations."""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


def migrate_v1_to_v2(data: dict[str, Any]) -> dict[str, Any]:
    """Migrate checkpoint data from version 1 to 2.

    Ensures all finding dictionaries (FindingDict) have all required fields, including
    new fields like cwe_id.
    """
    logger.info("Migrating checkpoint schema from version 1 to 2")
    data["schema_version"] = 2

    # Helper to migrate a single finding dictionary
    def migrate_finding(finding: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(finding, dict):
            return finding
        # Define defaults for required FindingDict fields
        defaults = {
            "category": "",
            "title": "",
            "url": "",
            "severity": "low",
            "confidence": 0.5,
            "score": 0,
            "evidence": {},
            "signals": [],
            "cwe_id": None,  # New field
        }
        for key, val in defaults.items():
            if key not in finding:
                finding[key] = val
        return finding

    # Helper to migrate finding lists in delta or state dicts
    def migrate_finding_lists(obj: Any) -> Any:
        if isinstance(obj, dict):
            migrated = {}
            for key, val in obj.items():
                if key in {
                    "findings",
                    "merged_findings",
                    "reportable_findings",
                    "vulnerabilities",
                    "active_scan_findings",
                    "nuclei_findings",
                } and isinstance(val, list):
                    migrated[key] = [migrate_finding(item) for item in val]
                else:
                    migrated[key] = migrate_finding_lists(val)
            return migrated
        if isinstance(obj, list):
            return [migrate_finding_lists(item) for item in obj]
        return obj

    # Run migration on stage_results and other keys
    for key in ["stage_results", "stage_deltas", "iterative_state", "nuclei_state"]:
        if key in data:
            data[key] = migrate_finding_lists(data[key])

    return data


class CheckpointMigrationRegistry:
    """Registry holding all checkpoint schema migrations."""

    LATEST_VERSION = 2

    def __init__(self) -> None:
        self._migrations = {
            1: migrate_v1_to_v2,
        }

    def migrate(self, data: dict[str, Any]) -> dict[str, Any]:
        """Apply all necessary forward migrations to bring the checkpoint up to latest version."""
        if not isinstance(data, dict):
            return data

        current_version = data.get("schema_version", 1)
        try:
            current_version = int(current_version)
        except (TypeError, ValueError):
            current_version = 1

        while current_version < self.LATEST_VERSION:
            migration_fn = self._migrations.get(current_version)
            if not migration_fn:
                logger.warning(
                    "No migration found from schema version %d to %d",
                    current_version,
                    current_version + 1,
                )
                break
            data = migration_fn(data)
            current_version = data.get("schema_version", current_version + 1)

        return data


GLOBAL_MIGRATION_REGISTRY = CheckpointMigrationRegistry()
