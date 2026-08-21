"""CRDT + WAL frontier. Evasion and WASM do not live here."""

from __future__ import annotations

from typing import Any


def neural_state_cls() -> Any:
    from src.core.frontier.state import NeuralState

    return NeuralState


def hybrid_clock_cls() -> Any:
    from src.core.frontier.state import HybridLogicalClock

    return HybridLogicalClock


def wal_cls() -> Any:
    from src.infrastructure.frontier.wal import FrontierWAL

    return FrontierWAL


def new_state() -> Any:
    return neural_state_cls()()


__all__ = ["hybrid_clock_cls", "neural_state_cls", "new_state", "wal_cls"]
