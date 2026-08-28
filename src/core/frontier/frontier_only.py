"""FRONTIER_ONLY: discover without PartitionWAL / authority.

When Raft/authority is unreachable, reconnaissance stages still run and
write local journal + findings spill. Authoritative settlement and
FINDING_CREATED via outbox are refused until READY.
"""

from __future__ import annotations

import logging
import os
import threading
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

AUTO_FRONTIER_ONLY_ENV = "AUTO_FRONTIER_ONLY_ON_AUTH_LOSS"
FRONTIER_ONLY_ALLOWLIST_ENV = "FRONTIER_ONLY_ALLOWLIST"
DEFAULT_ALLOWLIST = (
    "subdomains",
    "live_hosts",
    "urls",
    "recon_validation",
    "git_diff_crawl",
    "parameters",
)


def _env_flag(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() not in {"0", "false", "no", "off"}


def auto_frontier_only_enabled() -> bool:
    return _env_flag(AUTO_FRONTIER_ONLY_ENV, False)


def _allowlist() -> frozenset[str]:
    raw = os.environ.get(FRONTIER_ONLY_ALLOWLIST_ENV, "")
    if not raw.strip():
        return frozenset(DEFAULT_ALLOWLIST)
    return frozenset(part.strip() for part in raw.split(",") if part.strip())


@dataclass
class FrontierOnlyState:
    active: bool = False
    reason: str = ""
    allowlist: frozenset[str] = field(default_factory=_allowlist)

    def is_active(self) -> bool:
        return self.active

    def allows_stage(self, stage: str) -> bool:
        if not self.active:
            return True
        return str(stage) in self.allowlist

    def headers(self) -> dict[str, str]:
        if not self.active:
            return {}
        return {
            "X-Frontier-Only": "true",
            "X-Frontier-Reason": self.reason or "unknown",
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "active": self.active,
            "reason": self.reason,
            "allowlist": sorted(self.allowlist),
        }


_lock = threading.RLock()
_state = FrontierOnlyState()


def get_frontier_only_state() -> FrontierOnlyState:
    with _lock:
        return FrontierOnlyState(
            active=_state.active,
            reason=_state.reason,
            allowlist=frozenset(_state.allowlist),
        )


def is_frontier_only() -> bool:
    return get_frontier_only_state().is_active()


def enter_frontier_only(reason: str, *, force: bool = False) -> FrontierOnlyState:
    if not force and not auto_frontier_only_enabled():
        logger.warning(
            "FRONTIER_ONLY proposed but AUTO_FRONTIER_ONLY_ON_AUTH_LOSS=false: %s",
            reason,
        )
        return get_frontier_only_state()
    with _lock:
        _state.active = True
        _state.reason = reason
        _state.allowlist = _allowlist()
        logger.error("FRONTIER_ONLY entered: %s allowlist=%s", reason, sorted(_state.allowlist))
        return get_frontier_only_state()


def exit_frontier_only() -> FrontierOnlyState:
    with _lock:
        _state.active = False
        _state.reason = ""
        return get_frontier_only_state()


def reset_frontier_only() -> None:
    exit_frontier_only()


def stage_allowed(stage: str) -> bool:
    return get_frontier_only_state().allows_stage(stage)


def refuse_authoritative_settle() -> bool:
    return is_frontier_only()


__all__ = [
    "AUTO_FRONTIER_ONLY_ENV",
    "DEFAULT_ALLOWLIST",
    "FRONTIER_ONLY_ALLOWLIST_ENV",
    "FrontierOnlyState",
    "auto_frontier_only_enabled",
    "enter_frontier_only",
    "exit_frontier_only",
    "get_frontier_only_state",
    "is_frontier_only",
    "refuse_authoritative_settle",
    "reset_frontier_only",
    "stage_allowed",
]
