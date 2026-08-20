"""Checkpoint health, fencing, and stale-candidate helpers.

Shared by the generic ``manager.CheckpointManager`` autosave loop and the
pipeline ``strategies.CheckpointManager``. Recovery candidate selection
lives here so local-vs-remote fencing can be unit-tested without a store.
"""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass
from typing import Any

_UNHEALTHY_FAILURES = 5
DEFAULT_STALE_AFTER_SECONDS = 300.0
# Prefer a local checkpoint over a remote one unless the remote is this
# many completed stages ahead (split-brain fence).
_REMOTE_AHEAD_GRACE_STAGES = 5


class CheckpointFencedError(RuntimeError):
    """Raised when another writer holds a newer fence on this run."""


@dataclass
class CheckpointHealth:
    """Operator-visible autosave / persist health."""

    status: str = "healthy"
    consecutive_failures: int = 0
    last_error: str = ""
    last_success_at: float | None = None
    last_failure_at: float | None = None
    last_save_duration_ms: float | None = None
    fence_token: str = ""
    fenced: bool = False
    stale: bool = False
    saves: int = 0
    failures: int = 0

    def record_success(self, duration_ms: float | None = None) -> None:
        self.consecutive_failures = 0
        self.last_error = ""
        self.last_success_at = time.time()
        self.last_save_duration_ms = duration_ms
        self.status = "healthy"
        self.fenced = False
        self.stale = False
        self.saves += 1

    def record_failure(self, error: str, *, fenced: bool = False) -> None:
        self.consecutive_failures += 1
        self.last_error = str(error)
        self.last_failure_at = time.time()
        self.fenced = fenced
        self.failures += 1
        if fenced or self.consecutive_failures >= _UNHEALTHY_FAILURES:
            self.status = "unhealthy"
        else:
            self.status = "degraded"

    def to_dict(self) -> dict[str, Any]:
        return dict(asdict(self))


def is_checkpoint_stale(
    last_checkpoint_at: float | None,
    *,
    now: float | None = None,
    max_age_seconds: float = DEFAULT_STALE_AFTER_SECONDS,
    dirty: bool = False,
) -> bool:
    """Return True when a dirty checkpoint has not been saved recently."""
    if last_checkpoint_at is None:
        return False
    if max_age_seconds <= 0:
        return False
    age = (now if now is not None else time.time()) - float(last_checkpoint_at)
    return dirty and age > max_age_seconds


@dataclass(frozen=True)
class RecoveryCandidate:
    """Scored checkpoint candidate for local-vs-remote selection."""

    failed_neg: int
    completed: int
    timestamp: float
    source_node: str
    state: Any
    stale: bool = False

    def sort_key(self) -> tuple[int, int, float]:
        return (self.failed_neg, self.completed, self.timestamp)


def select_recovery_candidate(
    candidates: list[RecoveryCandidate],
    *,
    local_node_id: str = "",
    now: float | None = None,
    stale_after_seconds: float = DEFAULT_STALE_AFTER_SECONDS,
) -> RecoveryCandidate | None:
    """Pick the best checkpoint, fencing stale remotes in favour of local.

    Scoring (highest wins): fewest failed stages, then most completed
    stages, then newest timestamp. When ``local_node_id`` is set, a
    local candidate wins over a remote one unless the remote is both
    fresh and more than ``_REMOTE_AHEAD_GRACE_STAGES`` ahead.
    """
    if not candidates:
        return None

    clock = now if now is not None else time.time()
    scored: list[RecoveryCandidate] = []
    for item in candidates:
        stale = is_checkpoint_stale(
            item.timestamp,
            now=clock,
            max_age_seconds=stale_after_seconds,
            dirty=True,
        )
        scored.append(
            RecoveryCandidate(
                failed_neg=item.failed_neg,
                completed=item.completed,
                timestamp=item.timestamp,
                source_node=item.source_node,
                state=item.state,
                stale=stale,
            )
        )

    scored.sort(key=lambda item: item.sort_key(), reverse=True)
    best = scored[0]
    if not local_node_id:
        return best

    local_pool = [item for item in scored if item.source_node == local_node_id]
    if not local_pool:
        return best

    local_best = max(local_pool, key=lambda item: item.sort_key())
    remote = best.source_node and best.source_node != local_node_id
    if not remote:
        return best

    if best.stale and not local_best.stale:
        return local_best
    if local_best.completed >= best.completed - _REMOTE_AHEAD_GRACE_STAGES:
        return local_best
    return best


@dataclass
class FenceState:
    """Monotonic write fence for a single run."""

    token: str
    generation: int = 0
    fenced: bool = False

    def next_generation(self, observed: int = 0) -> int:
        self.generation = max(self.generation, observed) + 1
        return self.generation


def inspect_remote_fence(metadata: dict[str, Any] | None) -> tuple[str, int]:
    if not isinstance(metadata, dict):
        return "", 0
    token = str(metadata.get("fence_token") or "")
    try:
        generation = int(metadata.get("fence_generation") or 0)
    except (TypeError, ValueError):
        generation = 0
    return token, generation


def assert_writable_fence(
    local: FenceState,
    remote_token: str,
    remote_generation: int,
) -> None:
    """Raise if a different writer holds an equal-or-newer fence."""
    if (
        remote_token
        and remote_token != local.token
        and remote_generation >= local.generation
        and remote_generation > 0
    ):
        local.fenced = True
        raise CheckpointFencedError(
            f"run is fenced by token {remote_token[:8]} gen={remote_generation}"
        )
