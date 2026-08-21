"""RL evasion is opt-in. Default is disabled (no torch / PPO runtime)."""

from __future__ import annotations

import os
from typing import Any


def ppo_enabled() -> bool:
    return os.getenv("FEATURE_PPO", "false").strip().lower() in {"1", "true", "yes"}


def evasion_model() -> Any:
    if not ppo_enabled():
        raise RuntimeError("PPO evasion is disabled. Set FEATURE_PPO=true to enable.")
    from src.core.frontier.drl_evasion import PPOEvasionModel

    return PPOEvasionModel()


__all__ = ["evasion_model", "ppo_enabled"]
