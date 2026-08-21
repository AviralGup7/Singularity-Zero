from __future__ import annotations

from src.fuzzing.protocol import Mutator


class _Identity:
    def mutate(self, payload: bytes) -> bytes:
        return payload


def test_mutator_protocol_accepts_simple_impl() -> None:
    mutator: Mutator = _Identity()
    assert mutator.mutate(b"abc") == b"abc"
