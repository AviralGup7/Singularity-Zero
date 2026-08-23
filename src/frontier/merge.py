"""Merge two NeuralState snapshots."""

from __future__ import annotations

from typing import Any

from src.frontier import new_state
from src.frontier.deltas import snapshot_counts


def merge_snapshots(left: dict[str, Any] | None, right: dict[str, Any] | None) -> Any:
    state = new_state()
    if isinstance(left, dict):
        restored = (
            type(state).from_crdt_snapshot(left)
            if hasattr(type(state), "from_crdt_snapshot")
            else None
        )
        if restored is not None:
            state.merge(restored)
    if isinstance(right, dict):
        restored = type(state).from_crdt_snapshot(right)
        state.merge(restored)
    return state


def merge_counts(left: dict[str, Any] | None, right: dict[str, Any] | None) -> dict[str, int]:
    return snapshot_counts(merge_snapshots(left, right))
