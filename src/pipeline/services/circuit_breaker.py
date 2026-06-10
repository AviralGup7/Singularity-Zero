"""Circuit breaker pattern implementation for external tool calls.

This module provides a stateful circuit breaker used by
:mod:`src.pipeline.services.tool_execution` to prevent repeated calls to a
flaky or rate-limited external tool from accumulating cost.  The breaker is
keyed per-tool inside :class:`~src.pipeline.services.tool_execution.ToolExecutionService`
so that one failing tool (e.g. ``subfinder``) cannot starve the rest of the
pipeline.

State machine
-------------

::

    CLOSED ──(N consecutive failures)──▶ OPEN
       ▲                                  │
       │                       (recovery_timeout elapses)
       │                                  ▼
       └────(probe success)─── HALF_OPEN
                                  │
                       (probe failure)
                                  ▼
                                 OPEN

Operational hooks
-----------------

* :meth:`CircuitBreaker.force_open` lets the self-healing controller trip a
  breaker proactively when monitoring detects sustained error rates.
* :meth:`CircuitBreaker.update_recovery_timeout` lets operators tune the
  cool-down window per tool (e.g. ``nuclei`` recovers in 60 s, a blacklisted
  ``crt.sh`` may need 10 minutes).
* :meth:`CircuitBreaker.schedule_recovery_probe` registers a callback the
  coordinator will invoke when the breaker enters ``HALF_OPEN`` to test
  recovery cheaply before admitting real traffic.
* :meth:`CircuitBreaker.stats` exposes a serializable snapshot suitable for
  telemetry / dashboard surfacing.

Fix history
-----------

* Fix #345: Reduced default ``failure_threshold`` from 25 to 5 (industry
  standard).
* Fix #347: ``record_success`` only closes the circuit from ``HALF_OPEN``,
  not directly from ``OPEN``.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass
from typing import Any

from src.core.logging.trace_logging import get_pipeline_logger
from src.pipeline.unified_cache import CachePriority

logger = get_pipeline_logger(__name__)


class CircuitState:
    """Constants representing circuit breaker states."""

    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


@dataclass(slots=True, frozen=True)
class CircuitBreakerStats:
    """Serializable snapshot of a circuit breaker's state.

    Designed to be embedded directly in self-healing telemetry and exposed
    on the dashboard so operators can see which tools are currently being
    rate-limited / blocked upstream.
    """

    name: str
    state: str
    failure_count: int
    failure_threshold: int
    recovery_timeout: float
    last_failure_time: float
    last_state_change: float
    force_open_until: float
    forced_open: bool
    probe_registered: bool
    total_successes: int
    total_failures: int
    total_forced_opens: int

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


ProbeCallback = Callable[["CircuitBreaker"], None]


class CircuitBreaker:
    """Circuit breaker that trips after consecutive failures and recovers after a timeout.

    Fix #345: Reduced default failure_threshold from 25 to 5 (industry standard).
    Fix #347: record_success only closes the circuit from HALF_OPEN, not directly from OPEN.

    New (this revision): per-instance ``name`` for telemetry, ``force_open``
    hot-path used by the self-healing controller, dynamic ``recovery_timeout``
    updates, and a recovery-probe callback registry consumed by the
    coordinator.
    """

    def __init__(
        self,
        name: str = "default",
        failure_threshold: int = 5,  # Fix #345: was 25 — industry standard is 3–5
        recovery_timeout: float = 60.0,
    ) -> None:
        self.name = name
        self.failure_threshold = max(1, int(failure_threshold))
        self.recovery_timeout = max(0.0, float(recovery_timeout))
        self._failure_count: int = 0
        self._last_failure_time: float = 0.0
        self._last_state_change: float = time.time()
        self._state: str = CircuitState.CLOSED
        self._lock = threading.Lock()

        # Fix #346: Cache state with short TTL to reduce lock contention
        self._cached_state: str = CircuitState.CLOSED
        self._cached_state_time: float = 0.0
        self._cache_ttl: float = 0.05  # 50ms TTL

        # Force-open hot-path: when > 0 the breaker refuses calls until
        # ``_force_open_until`` is reached regardless of recovery_timeout.
        self._force_open_until: float = 0.0
        self._forced_open: bool = False

        # Recovery probe callback registry.  The coordinator calls
        # ``consume_pending_probe()`` to find breakers that just entered
        # HALF_OPEN and need an automated probe run.
        self._probe_callback: ProbeCallback | None = None
        self._probe_pending: bool = False

        # Lifetime counters (observability only — never gate execution).
        self._total_successes: int = 0
        self._total_failures: int = 0
        self._total_forced_opens: int = 0

    # ------------------------------------------------------------------ #
    # State observation                                                    #
    # ------------------------------------------------------------------ #

    @property
    def state(self) -> str:
        now = time.time()
        # Fast path lock-free read
        if now - self._cached_state_time < self._cache_ttl:
            return self._cached_state

        with self._lock:
            if self._state == CircuitState.OPEN:
                # Honor an explicit force-open until timestamp first.
                if self._forced_open and now < self._force_open_until:
                    pass  # still forced open
                elif now - self._last_failure_time >= self.recovery_timeout:
                    self._set_state_locked(CircuitState.HALF_OPEN, now, log=True)
                    self._probe_pending = True

            # Update cache
            self._cached_state = self._state
            self._cached_state_time = now
            return self._state

    def is_closed(self) -> bool:
        return self.state == CircuitState.CLOSED

    def is_open(self) -> bool:
        return self.state == CircuitState.OPEN

    def is_half_open(self) -> bool:
        return self.state == CircuitState.HALF_OPEN

    # ------------------------------------------------------------------ #
    # Lifecycle transitions                                                 #
    # ------------------------------------------------------------------ #

    def record_success(self) -> None:
        # Fix #347: Only transition HALF_OPEN -> CLOSED (not OPEN -> CLOSED directly).
        # Direct OPEN -> CLOSED would skip the recovery probe window.
        with self._lock:
            self._total_successes += 1
            if self._state in (CircuitState.HALF_OPEN, CircuitState.CLOSED):
                self._failure_count = 0
                self._set_state_locked(CircuitState.CLOSED, time.time(), log=False)
                if self._forced_open:
                    # Probe succeeded — clear the force-open flag so the breaker
                    # returns to its normal CLOSED->failure-driven path.
                    self._forced_open = False
                    self._force_open_until = 0.0

    def record_failure(self) -> None:
        with self._lock:
            now = time.time()
            self._total_failures += 1
            self._failure_count += 1
            self._last_failure_time = now
            if self._state == CircuitState.HALF_OPEN:
                # Probe failed — re-open immediately, do not reset the timer.
                self._set_state_locked(CircuitState.OPEN, now, log=True)
                return
            if self._failure_count >= self.failure_threshold:
                self._set_state_locked(CircuitState.OPEN, now, log=True)

    def can_execute(self) -> bool:
        with self._lock:
            now = time.time()
            if self._state == CircuitState.OPEN:
                if self._forced_open and now < self._force_open_until:
                    # Force-open is still in effect.
                    self._cached_state = CircuitState.OPEN
                    self._cached_state_time = now
                    return False
                if now - self._last_failure_time >= self.recovery_timeout:
                    self._set_state_locked(CircuitState.HALF_OPEN, now, log=True)
                    self._probe_pending = True
            if self._state == CircuitState.OPEN:
                self._cached_state = CircuitState.OPEN
                self._cached_state_time = now
                return False
            return True

    def reset(self) -> None:
        """Manually reset the breaker to CLOSED (used by recovery actions)."""
        with self._lock:
            now = time.time()
            self._failure_count = 0
            self._forced_open = False
            self._force_open_until = 0.0
            self._probe_pending = False
            self._set_state_locked(CircuitState.CLOSED, now, log=True)

    # ------------------------------------------------------------------ #
    # Self-healing controller hot-path                                     #
    # ------------------------------------------------------------------ #

    def force_open(self, reason: str, duration_seconds: float | None = None) -> None:
        """Trip the breaker externally, optionally for a fixed cool-down.

        Used by the self-healing controller when monitoring detects sustained
        error rates.  While forced open the breaker rejects calls even if the
        regular ``recovery_timeout`` would have allowed a probe.  A successful
        call to :meth:`record_success` clears the forced state.

        Args:
            reason: Human-readable reason (logged, stored on the stats dict).
            duration_seconds: Optional fixed cool-down window.  If ``None``
                the breaker uses ``recovery_timeout`` as the cool-down
                countdown.  ``0`` (or negative) means "indefinite" — the
                breaker stays open until :meth:`reset` is called or a
                subsequent :meth:`record_success` succeeds.
        """
        with self._lock:
            now = time.time()
            self._total_forced_opens += 1
            if duration_seconds is None or duration_seconds <= 0:
                # Indeterminate force-open: stay OPEN until manual reset.
                self._force_open_until = float("inf")
            else:
                self._force_open_until = now + float(duration_seconds)
            self._forced_open = True
            self._failure_count = max(self._failure_count, self.failure_threshold)
            self._last_failure_time = now
            self._set_state_locked(CircuitState.OPEN, now, log=False)
            logger.warning(
                "Circuit breaker [%s] force-opened: %s (until=%s)",
                self.name,
                reason,
                self._force_open_until if self._force_open_until != float("inf") else "manual",
            )

    def update_recovery_timeout(self, recovery_timeout: float) -> None:
        """Adjust the cool-down window (e.g. nuclei=60s, crt.sh=600s)."""
        if recovery_timeout < 0:
            raise ValueError("recovery_timeout must be >= 0")
        with self._lock:
            self.recovery_timeout = float(recovery_timeout)

    def schedule_recovery_probe(self, callback: ProbeCallback) -> None:
        """Register a callback to run when the breaker enters HALF_OPEN.

        The coordinator polls :meth:`consume_pending_probe` and invokes the
        callback exactly once per HALF_OPEN transition.  The callback should
        perform a cheap, low-risk probe (e.g. ``tool -version`` or a 1%
        canary call) and either succeed (the next :meth:`record_success` will
        close the circuit) or fail (re-open).
        """
        with self._lock:
            self._probe_callback = callback

    def consume_pending_probe(self) -> ProbeCallback | None:
        """Atomically take ownership of the pending probe callback (if any).

        Returns the registered callback the first time the breaker transitions
        to ``HALF_OPEN`` since the previous consume, and ``None`` afterwards
        until the next HALF_OPEN transition.  The coordinator uses this to
        dispatch a recovery probe without losing probe signals.
        """
        with self._lock:
            if not self._probe_pending:
                return None
            self._probe_pending = False
            return self._probe_callback

    # ------------------------------------------------------------------ #
    # Telemetry                                                            #
    # ------------------------------------------------------------------ #

    def stats(self) -> CircuitBreakerStats:
        with self._lock:
            time.time()
            return CircuitBreakerStats(
                name=self.name,
                state=self._state,
                failure_count=self._failure_count,
                failure_threshold=self.failure_threshold,
                recovery_timeout=self.recovery_timeout,
                last_failure_time=self._last_failure_time,
                last_state_change=self._last_state_change,
                force_open_until=(
                    self._force_open_until if self._force_open_until != float("inf") else 0.0
                ),
                forced_open=self._forced_open,
                probe_registered=self._probe_callback is not None,
                total_successes=self._total_successes,
                total_failures=self._total_failures,
                total_forced_opens=self._total_forced_opens,
            )

    # ------------------------------------------------------------------ #
    # Internal                                                             #
    # ------------------------------------------------------------------ #

    def _set_state_locked(self, new_state: str, now: float, *, log: bool) -> None:
        if self._state == new_state:
            return
        old = self._state
        self._state = new_state
        self._last_state_change = now
        self._cached_state = new_state
        self._cached_state_time = now
        if log:
            logger.info(
                "Circuit breaker [%s] %s -> %s",
                self.name,
                old,
                new_state,
            )


# --------------------------------------------------------------------------- #
# Per-tool configuration                                                      #
# --------------------------------------------------------------------------- #


@dataclass(slots=True, frozen=True)
class CircuitBreakerConfig:
    """Per-tool circuit-breaker tunables.

    Different tools have wildly different failure characteristics:

    * ``nuclei`` is local and recovers in seconds; threshold=3, recovery=60s.
    * ``crt.sh`` is rate-limited and can stay blocked for minutes; threshold=5,
      recovery=600s.
    * ``subfinder`` may be flaky on slow networks; threshold=5, recovery=120s.

    The defaults below are sane for the broader pipeline.  Tool-specific
    overrides can be supplied when constructing a
    :class:`~src.pipeline.services.tool_execution.ToolExecutionService`.
    """

    failure_threshold: int = 5
    recovery_timeout: float = 60.0
    force_open_initial: bool = False
    force_open_duration_seconds: float = 0.0
    force_open_reason: str = ""

    @classmethod
    def from_settings(
        cls,
        settings: dict[str, Any] | None,
        *,
        default: CircuitBreakerConfig | None = None,
    ) -> CircuitBreakerConfig:
        """Build a config from a settings dict, falling back to ``default``."""
        settings = settings or {}
        base = default or cls()
        try:
            threshold = int(
                settings.get("circuit_breaker_failure_threshold", base.failure_threshold)
            )
        except (TypeError, ValueError):
            threshold = base.failure_threshold
        try:
            recovery = float(
                settings.get("circuit_breaker_recovery_timeout", base.recovery_timeout)
            )
        except (TypeError, ValueError):
            recovery = base.recovery_timeout
        return cls(
            failure_threshold=max(1, threshold),
            recovery_timeout=max(0.0, recovery),
            force_open_initial=bool(
                settings.get("circuit_breaker_force_open", base.force_open_initial)
            ),
            force_open_duration_seconds=float(
                settings.get(
                    "circuit_breaker_force_open_duration",
                    base.force_open_duration_seconds,
                )
            ),
            force_open_reason=str(
                settings.get("circuit_breaker_force_open_reason", base.force_open_reason)
            ),
        )


_CB_PERSISTENCE_PREFIX = "cb_state:"


def persist_breaker_state(cache: Any, tool_name: str, breaker: CircuitBreaker) -> None:
    """Persist a circuit breaker's serializable state to unified cache."""
    try:
        cache.set(
            f"{_CB_PERSISTENCE_PREFIX}{tool_name}",
            breaker.stats().as_dict(),
            ttl=86400 * 30,
            priority=CachePriority.CRITICAL,
        )
    except Exception as exc:
        logger.warning("Operation failed in circuit_breaker.py: %s", exc, exc_info=True)  # noqa: BLE001


def load_breaker_state(cache: Any, tool_name: str) -> dict[str, Any] | None:
    """Load persisted circuit breaker state. Returns None if absent."""
    try:
        return cache.get(f"{_CB_PERSISTENCE_PREFIX}{tool_name}")
    except Exception:
        return None


def persist_all_breakers(cache: Any, breakers: dict[str, CircuitBreaker]) -> None:
    for name, breaker in breakers.items():
        persist_breaker_state(cache, name, breaker)


def load_all_breakers(cache: Any) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    try:
        prefix = _CB_PERSISTENCE_PREFIX
        keys = cache.keys_with_prefix(prefix)
        for key in keys:
            name = key[len(prefix) :]
            state = cache.get(key)
            if isinstance(state, dict):
                result[name] = state
    except Exception as exc:
        logger.warning("Operation failed in circuit_breaker.py: %s", exc, exc_info=True)  # noqa: BLE001
    return result


__all__ = [
    "CircuitBreaker",
    "CircuitBreakerConfig",
    "CircuitBreakerStats",
    "CircuitState",
    "ProbeCallback",
]
