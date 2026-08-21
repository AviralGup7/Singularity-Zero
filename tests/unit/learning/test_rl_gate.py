from __future__ import annotations

import pytest

from src.learning.rl import evasion_model, ppo_enabled


def test_ppo_disabled_by_default(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.delenv("FEATURE_PPO", raising=False)
    assert ppo_enabled() is False
    with pytest.raises(RuntimeError, match="disabled"):
        evasion_model()
