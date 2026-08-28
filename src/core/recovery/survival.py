"""Minimum Viable Survival mode (SURVIVAL_READONLY).

Intentional degradation: keep operator surface + forensics alive when WAL,
quorum, or disk is wrong. Mutations are refused. Reads, export, and DLQ
inspection remain available.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

logger = logging.getLogger(__name__)

AUTO_ENTER_ENV = "AUTO_ENTER_SURVIVAL_ON_CORRUPT"


class SurvivalMode(StrEnum):
    NORMAL = "NORMAL"
    SURVIVAL_READONLY = "SURVIVAL_READONLY"


_MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


@dataclass
class SurvivalState:
    mode: SurvivalMode = SurvivalMode.NORMAL
    reason: str = ""
    since_unix: float = 0.0
    commit_index: int = 0
    state_hash: str = ""
    lag_seconds: float = 0.0
    quorum: bool = True
    blocked_actions: tuple[str, ...] = ()
    extra: dict[str, Any] = field(default_factory=dict)

    def is_survival(self) -> bool:
        return self.mode is SurvivalMode.SURVIVAL_READONLY

    def to_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode.value,
            "reason": self.reason,
            "since": self.since_unix,
            "commitIndex": self.commit_index,
            "state_hash": self.state_hash,
            "lag": self.lag_seconds,
            "quorum": self.quorum,
            "blocked_actions": list(self.blocked_actions),
            **self.extra,
        }

    def headers(self) -> dict[str, str]:
        if not self.is_survival():
            return {}
        return {
            "X-Survival-Mode": "true",
            "X-Survival-Reason": self.reason or "unknown",
        }


_lock = threading.RLock()
_state = SurvivalState()


def get_survival_state() -> SurvivalState:
    with _lock:
        return SurvivalState(
            mode=_state.mode,
            reason=_state.reason,
            since_unix=_state.since_unix,
            commit_index=_state.commit_index,
            state_hash=_state.state_hash,
            lag_seconds=_state.lag_seconds,
            quorum=_state.quorum,
            blocked_actions=_state.blocked_actions,
            extra=dict(_state.extra),
        )


def is_survival() -> bool:
    return get_survival_state().is_survival()


def auto_enter_enabled() -> bool:
    raw = os.environ.get(AUTO_ENTER_ENV, "false").strip().lower()
    return raw in {"1", "true", "yes", "on"}


def enter_survival(
    reason: str,
    *,
    commit_index: int = 0,
    state_hash: str = "",
    force: bool = False,
) -> SurvivalState:
    """Enter SURVIVAL_READONLY. Honors AUTO_ENTER_SURVIVAL_ON_CORRUPT unless force=True."""
    if not force and not auto_enter_enabled():
        logger.warning(
            "Survival proposed but AUTO_ENTER_SURVIVAL_ON_CORRUPT=false: %s",
            reason,
        )
        state = get_survival_state()
        state.extra["proposal"] = reason
        return state
    with _lock:
        _state.mode = SurvivalMode.SURVIVAL_READONLY
        _state.reason = reason
        _state.since_unix = time.time()
        _state.commit_index = int(commit_index)
        _state.state_hash = str(state_hash or "")
        _state.quorum = False
        _state.blocked_actions = (
            "mutating_command",
            "reserve_budget",
            "scan_run",
            "authority_transfer",
        )
        logger.error("SURVIVAL_READONLY entered: %s", reason)
        return get_survival_state()


def exit_survival() -> SurvivalState:
    with _lock:
        _state.mode = SurvivalMode.NORMAL
        _state.reason = ""
        _state.since_unix = 0.0
        _state.blocked_actions = ()
        _state.quorum = True
        return get_survival_state()


def reset_survival() -> None:
    """Test helper."""
    exit_survival()


def mutation_blocked(method: str) -> bool:
    return is_survival() and method.upper() in _MUTATING_METHODS


def assert_mutation_allowed(action: str = "mutate") -> None:
    if is_survival():
        raise PermissionError(
            f"SURVIVAL_READONLY: refusing {action} ({get_survival_state().reason})"
        )


__all__ = [
    "AUTO_ENTER_ENV",
    "SurvivalMode",
    "SurvivalState",
    "assert_mutation_allowed",
    "auto_enter_enabled",
    "enter_survival",
    "exit_survival",
    "get_survival_state",
    "is_survival",
    "mutation_blocked",
    "reset_survival",
]
