"""Adaptive provider health tracking with circuit-breaking.

Before this module existed, a provider that hit an authentication wall
(``Spyse`` sunset endpoint, expired ``SecurityTrails`` key, revoked
``Chaos`` API key) would keep being invoked on every run, burning
wall-clock time and HTTP budget on calls that were guaranteed to
return zero results.  The aggregator had no memory across runs: every
failure cost the same as the previous one.

:class:`ProviderHealthRegistry` is a lightweight, file-backed (with an
in-memory fallback) tracker of per-provider health state.  After
``failure_threshold`` consecutive failures a provider is marked
``circuit_open`` and the aggregator short-circuits it for
``cool_down_seconds`` instead of running it.  A single successful call
resets the failure counter and re-closes the breaker.

Design notes:

* State is JSON-persisted under ``~/.cache/cyber-pipeline/collector_health.json``
  (overridable via ``COLLECTOR_HEALTH_STATE_PATH`` for tests / CI).
* The registry never raises if persistence fails – health tracking is
  a *best effort* enhancement, never a hard dependency.
* The default failure threshold is conservative (3 consecutive
  failures) and the cool-down is short (15 minutes) so the cost of a
  false positive is bounded to a quarter-hour outage of one provider.
* The implementation is thread-safe (``threading.RLock``).
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
import threading
import time
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

DEFAULT_FAILURE_THRESHOLD = 3
DEFAULT_COOL_DOWN_SECONDS = 15 * 60  # 15 minutes
_ENV_STATE_PATH = "COLLECTOR_HEALTH_STATE_PATH"


@dataclass
class ProviderHealth:
    """Mutable per-provider health record.

    Attributes:
        consecutive_failures: Number of failed runs since the most
            recent successful run.  Reset to zero on success.
        last_failure_at: Unix timestamp of the most recent failure
            (``0`` when never failed).
        last_success_at: Unix timestamp of the most recent success
            (``0`` when never succeeded).
        circuit_opened_at: Unix timestamp when the breaker tripped
            (``0`` when closed).
        total_failures: Cumulative failure counter across all runs.
        total_successes: Cumulative success counter across all runs.
        last_error: String description of the most recent failure, or
            ``None``.
        ema_duration_seconds: Exponentially weighted moving average of
            successful-run duration.  Useful for adaptive timeouts.
    """

    consecutive_failures: int = 0
    last_failure_at: float = 0.0
    last_success_at: float = 0.0
    circuit_opened_at: float = 0.0
    total_failures: int = 0
    total_successes: int = 0
    last_error: str | None = None
    ema_duration_seconds: float = 0.0

    def is_circuit_open(self, *, cool_down_seconds: float, now: float | None = None) -> bool:
        if self.circuit_opened_at <= 0:
            return False
        current = now if now is not None else time.time()
        return (current - self.circuit_opened_at) < cool_down_seconds


class ProviderHealthRegistry:
    """Thread-safe registry of provider health records.

    A single global instance, :data:`HEALTH_REGISTRY`, is shared by the
    aggregator.  Tests construct their own instance with an isolated
    state path via :func:`new_registry_for_tests`.
    """

    def __init__(
        self,
        *,
        state_path: Path | None = None,
        failure_threshold: int = DEFAULT_FAILURE_THRESHOLD,
        cool_down_seconds: float = DEFAULT_COOL_DOWN_SECONDS,
    ) -> None:
        self._state_path = state_path
        self._failure_threshold = max(1, int(failure_threshold))
        self._cool_down_seconds = max(1.0, float(cool_down_seconds))
        self._lock = threading.RLock()
        self._records: dict[str, ProviderHealth] = {}
        self._loaded = False

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def failure_threshold(self) -> int:
        return self._failure_threshold

    @property
    def cool_down_seconds(self) -> float:
        return self._cool_down_seconds

    def is_circuit_open(self, provider: str, *, now: float | None = None) -> bool:
        """Return True when *provider* is currently in the OPEN state."""
        with self._lock:
            self._lazy_load()
            record = self._records.get(provider)
            if record is None:
                return False
            opened = record.is_circuit_open(cool_down_seconds=self._cool_down_seconds, now=now)
            if not opened and record.circuit_opened_at > 0:
                # Cool-down elapsed: half-open the breaker so the next
                # call has a chance to fully reset it.
                record.circuit_opened_at = 0.0
            return opened

    def cool_down_remaining(self, provider: str, *, now: float | None = None) -> float:
        """Seconds until the breaker closes again (0 when closed)."""
        with self._lock:
            self._lazy_load()
            record = self._records.get(provider)
            if record is None or record.circuit_opened_at <= 0:
                return 0.0
            current = now if now is not None else time.time()
            remaining = self._cool_down_seconds - (current - record.circuit_opened_at)
            return max(0.0, remaining)

    def record_success(
        self,
        provider: str,
        *,
        duration_seconds: float = 0.0,
        now: float | None = None,
    ) -> None:
        """Update state to reflect a successful provider run.

        Resets the consecutive-failure counter, closes the breaker,
        bumps ``total_successes`` and updates the EMA duration.
        """
        current = now if now is not None else time.time()
        with self._lock:
            self._lazy_load()
            record = self._records.setdefault(provider, ProviderHealth())
            record.consecutive_failures = 0
            record.circuit_opened_at = 0.0
            record.last_success_at = current
            record.total_successes += 1
            record.last_error = None
            # 0.3 weight for the new sample, 0.7 for the historical EMA
            # — a fast-but-stable adaptation.
            if record.ema_duration_seconds <= 0:
                record.ema_duration_seconds = float(duration_seconds)
            else:
                record.ema_duration_seconds = 0.7 * record.ema_duration_seconds + 0.3 * float(
                    duration_seconds
                )
            self._save_unlocked()

    def record_failure(
        self,
        provider: str,
        *,
        error: str | None = None,
        now: float | None = None,
    ) -> bool:
        """Update state to reflect a failed provider run.

        Returns ``True`` when this failure trips the breaker (i.e. the
        consecutive-failure count reached the configured threshold for
        the first time).
        """
        current = now if now is not None else time.time()
        with self._lock:
            self._lazy_load()
            record = self._records.setdefault(provider, ProviderHealth())
            record.consecutive_failures += 1
            record.total_failures += 1
            record.last_failure_at = current
            record.last_error = error
            tripped = False
            if record.consecutive_failures >= self._failure_threshold:
                if record.circuit_opened_at <= 0:
                    tripped = True
                record.circuit_opened_at = current
                if tripped:
                    logger.warning(
                        "Provider %s circuit breaker OPEN after %d consecutive failures "
                        "(last error: %s); cooling down for %ds",
                        provider,
                        record.consecutive_failures,
                        error or "<no error>",
                        int(self._cool_down_seconds),
                    )
            self._save_unlocked()
            return tripped

    def snapshot(self) -> dict[str, dict[str, Any]]:
        """Return a JSON-serialisable view of all tracked providers."""
        with self._lock:
            self._lazy_load()
            return {name: asdict(record) for name, record in self._records.items()}

    def known_providers(self) -> Iterable[str]:
        with self._lock:
            self._lazy_load()
            return tuple(self._records.keys())

    def reset(self, provider: str | None = None) -> None:
        """Forget all health state (or just for one provider)."""
        with self._lock:
            self._lazy_load()
            if provider is None:
                self._records.clear()
            else:
                self._records.pop(provider, None)
            self._save_unlocked()

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _resolve_state_path(self) -> Path | None:
        if self._state_path is not None:
            return self._state_path
        env_override = os.environ.get(_ENV_STATE_PATH)
        if env_override:
            path = Path(env_override).expanduser()
            self._state_path = path
            return path
        # Default to user cache dir.  We fall back to a temp dir when
        # ``HOME`` is unset (CI containers).
        try:
            home = Path.home()
        except RuntimeError:
            home = Path(tempfile.gettempdir())
        cache_dir = home / ".cache" / "cyber-pipeline"
        path = cache_dir / "collector_health.json"
        self._state_path = path
        return path

    def _lazy_load(self) -> None:
        if self._loaded:
            return
        self._loaded = True
        path = self._resolve_state_path()
        if path is None or not path.exists():
            return
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            logger.debug("Failed to load collector health state from %s: %s", path, exc)
            return
        if not isinstance(raw, dict):
            return
        for provider_name, record_dict in raw.items():
            if not isinstance(record_dict, dict):
                continue
            try:
                self._records[provider_name] = ProviderHealth(
                    consecutive_failures=int(record_dict.get("consecutive_failures", 0)),
                    last_failure_at=float(record_dict.get("last_failure_at", 0.0)),
                    last_success_at=float(record_dict.get("last_success_at", 0.0)),
                    circuit_opened_at=float(record_dict.get("circuit_opened_at", 0.0)),
                    total_failures=int(record_dict.get("total_failures", 0)),
                    total_successes=int(record_dict.get("total_successes", 0)),
                    last_error=record_dict.get("last_error"),
                    ema_duration_seconds=float(record_dict.get("ema_duration_seconds", 0.0)),
                )
            except (TypeError, ValueError) as exc:
                logger.debug(
                    "Discarding invalid health record for %s: %s",
                    provider_name,
                    exc,
                )

    def _save_unlocked(self) -> None:
        path = self._resolve_state_path()
        if path is None:
            return
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            payload = {name: asdict(record) for name, record in self._records.items()}
            tmp = path.with_suffix(path.suffix + ".tmp")
            tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
            tmp.replace(path)
        except OSError as exc:
            logger.debug("Failed to persist collector health state to %s: %s", path, exc)


# ---------------------------------------------------------------------------
# Process-wide singleton
# ---------------------------------------------------------------------------

HEALTH_REGISTRY = ProviderHealthRegistry()


def is_circuit_open(provider: str) -> bool:
    return HEALTH_REGISTRY.is_circuit_open(provider)


def record_success(provider: str, *, duration_seconds: float = 0.0) -> None:
    HEALTH_REGISTRY.record_success(provider, duration_seconds=duration_seconds)


def record_failure(provider: str, *, error: str | None = None) -> bool:
    return HEALTH_REGISTRY.record_failure(provider, error=error)


def cool_down_remaining(provider: str) -> float:
    return HEALTH_REGISTRY.cool_down_remaining(provider)


def new_registry_for_tests(state_path: Path | None = None) -> ProviderHealthRegistry:
    """Return a fresh, isolated registry suitable for unit tests."""
    return ProviderHealthRegistry(state_path=state_path)


def reset_health_state() -> None:
    """Clear the global :data:`HEALTH_REGISTRY` in-memory + on-disk state.

    Use this from test fixtures or maintenance scripts when you want to
    start from a clean slate.  The aggregator will rebuild the file
    naturally on the next ``record_*`` call.
    """
    HEALTH_REGISTRY.reset()
    HEALTH_REGISTRY._loaded = True  # noqa: SLF001 - intentional: we just persisted an empty state


__all__ = [
    "ProviderHealth",
    "ProviderHealthRegistry",
    "HEALTH_REGISTRY",
    "is_circuit_open",
    "record_success",
    "record_failure",
    "cool_down_remaining",
    "new_registry_for_tests",
    "reset_health_state",
    "DEFAULT_FAILURE_THRESHOLD",
    "DEFAULT_COOL_DOWN_SECONDS",
]
