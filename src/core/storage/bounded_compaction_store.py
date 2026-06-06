from __future__ import annotations

import copy
from typing import Any

from src.core.frontier.state import CRDTCompactionBudget, NeuralState, compact_state
from src.core.storage.interfaces import CheckpointStore, VersionId


class BoundedCompactionStateStore:
    """
    Transparent CheckpointStore wrapper that enforces compaction budgets
    at the persistence layer before writing checkpoints.
    """

    def __init__(
        self,
        backend: CheckpointStore,
        budget: CRDTCompactionBudget | None = None,
        max_tombstone_age_seconds: float = 3600.0,
    ) -> None:
        self.backend = backend
        self.budget = budget or CRDTCompactionBudget()
        self.max_tombstone_age_seconds = max_tombstone_age_seconds

    def write(self, run_id: str, version: int, payload: dict[str, Any]) -> VersionId:
        """
        Intercept checkpoint writes to perform budget-aware compaction.
        Supports both raw snapshot dictionaries and crdt-snapshot envelopes.
        """
        payload_copy = copy.deepcopy(payload)

        if "sets" in payload_copy or payload_copy.get("format") == "neural-state-crdt-v2":
            state = NeuralState.from_crdt_snapshot(payload_copy)
            compact_state(state, self.budget, self.max_tombstone_age_seconds)
            _clear_legacy_state_keys(payload_copy)
            payload_copy.update(state.to_crdt_snapshot())
        elif "subdomains" in payload_copy or "urls" in payload_copy or "findings" in payload_copy:
            state = NeuralState.from_crdt_snapshot(payload_copy)
            compact_state(state, self.budget, self.max_tombstone_age_seconds)
            _clear_legacy_state_keys(payload_copy)
            payload_copy.update(state.get_snapshot())

        return self.backend.write(run_id, version, payload_copy)

    def read_latest(self, run_id: str | None = None) -> dict[str, Any] | None:
        return self.backend.read_latest(run_id)

    def list_run_ids(self) -> list[str]:
        return self.backend.list_run_ids()

    def read_version_by_id(
        self, run_id: str, version_id: VersionId
    ) -> dict[str, Any] | None:
        return self.backend.read_version_by_id(run_id, version_id)

    def list_version_ids(self, run_id: str) -> list[VersionId]:
        return self.backend.list_version_ids(run_id)

    def delete_version(self, run_id: str, version_id: VersionId) -> None:
        self.backend.delete_version(run_id, version_id)

    def write_context_snapshot(
        self, run_id: str, stage_name: str, payload: dict[str, Any]
    ) -> VersionId:
        return self.backend.write_context_snapshot(run_id, stage_name, payload)

    def read_context_snapshot(
        self, run_id: str, stage_name: str
    ) -> dict[str, Any] | None:
        return self.backend.read_context_snapshot(run_id, stage_name)

    def write_stage_delta(
        self,
        run_id: str,
        stage_name: str,
        sequence: int,
        payload: dict[str, Any],
    ) -> VersionId:
        return self.backend.write_stage_delta(run_id, stage_name, sequence, payload)

    def list_stage_deltas(
        self, run_id: str, stage_name: str
    ) -> list[dict[str, Any]]:
        return self.backend.list_stage_deltas(run_id, stage_name)


_LEGACY_STATE_KEYS = ("subdomains", "urls", "findings", "live_hosts")


def _clear_legacy_state_keys(payload: dict[str, Any]) -> None:
    """Remove legacy state keys from ``payload`` so a subsequent ``update``
    cannot resurrect stale values from the original dict.
    """
    for key in _LEGACY_STATE_KEYS:
        payload.pop(key, None)
