from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

from src.core.frontier.state import CRDTCompactionBudget, NeuralState, compact_state
from src.core.storage.interfaces import CheckpointStore


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

    def write(self, run_id: str, version: int, payload: dict[str, Any]) -> str | Path:
        """
        Intercept checkpoint writes to perform budget-aware compaction.
        Supports both raw snapshot dictionaries and crdt-snapshot envelopes.
        """
        payload_copy = copy.deepcopy(payload)

        # Intercept and compact the state before saving
        if "sets" in payload_copy or payload_copy.get("format") == "neural-state-crdt-v2":
            state = NeuralState.from_crdt_snapshot(payload_copy)
            compact_state(state, self.budget, self.max_tombstone_age_seconds)
            payload_copy.update(state.to_crdt_snapshot())
        elif "subdomains" in payload_copy or "urls" in payload_copy or "findings" in payload_copy:
            state = NeuralState.from_crdt_snapshot(payload_copy)
            compact_state(state, self.budget, self.max_tombstone_age_seconds)
            payload_copy.update(state.get_snapshot())

        return self.backend.write(run_id, version, payload_copy)

    def read_latest(self, run_id: str | None = None) -> dict[str, Any] | None:
        return self.backend.read_latest(run_id)

    def read_version(self, path: str | Path) -> dict[str, Any] | None:
        return self.backend.read_version(path)

    def list_versions(self, run_id: str) -> list[str | Path]:
        return self.backend.list_versions(run_id)

    def delete(self, path: str | Path) -> None:
        self.backend.delete(path)
