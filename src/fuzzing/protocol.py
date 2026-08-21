"""Mutator contract. Core must not import fuzzing implementations."""

from __future__ import annotations

from typing import Protocol


class Mutator(Protocol):
    def mutate(self, payload: bytes) -> bytes: ...


__all__ = ["Mutator"]
