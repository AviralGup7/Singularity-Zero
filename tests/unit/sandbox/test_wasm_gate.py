from __future__ import annotations

from src.sandbox import wasm_enabled


def test_wasm_disabled_by_default(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.delenv("FEATURE_WASM_PLUGINS", raising=False)
    assert wasm_enabled() is False
