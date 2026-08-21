from __future__ import annotations

import importlib.util
from pathlib import Path


def _load_protocol():
    path = Path(__file__).resolve().parents[3] / "src" / "fuzzing" / "protocol.py"
    spec = importlib.util.spec_from_file_location("fuzzing_protocol_isolated", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_mutator_protocol_accepts_simple_impl() -> None:
    module = _load_protocol()

    class Identity:
        def mutate(self, payload: bytes) -> bytes:
            return payload

    mutator: module.Mutator = Identity()  # type: ignore[name-defined]
    assert mutator.mutate(b"abc") == b"abc"
