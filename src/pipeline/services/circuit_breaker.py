"""Circuit breaker pattern implementation for external tool calls."""

import threading
import time

from src.core.logging.trace_logging import get_pipeline_logger

logger = get_pipeline_logger(__name__)


class CircuitState:
    """Constants representing circuit breaker states."""

    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitBreaker:
    """Circuit breaker that trips after consecutive failures and recovers after a timeout.

    Fix #345: Reduced default failure_threshold from 25 to 5 (industry standard).
    Fix #347: record_success only closes the circuit from HALF_OPEN, not directly from OPEN.
    """

    def __init__(
        self,
        failure_threshold: int = 5,  # Fix #345: was 25 — industry standard is 3–5
        recovery_timeout: float = 60.0,
    ) -> None:
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self._failure_count: int = 0
        self._last_failure_time: float = 0.0
        self._state: str = CircuitState.CLOSED
        self._lock = threading.Lock()
        
        # Fix #346: Cache state with short TTL to reduce lock contention
        self._cached_state: str = CircuitState.CLOSED
        self._cached_state_time: float = 0.0
        self._cache_ttl: float = 0.05  # 50ms TTL

    @property
    def state(self) -> str:
        now = time.time()
        # Fast path lock-free read
        if now - self._cached_state_time < self._cache_ttl:
            return self._cached_state

        with self._lock:
            if self._state == CircuitState.OPEN:
                if now - self._last_failure_time >= self.recovery_timeout:
                    self._state = CircuitState.HALF_OPEN
                    logger.info("Circuit breaker HALF_OPEN: attempting recovery")
            
            # Update cache
            self._cached_state = self._state
            self._cached_state_time = now
            return self._state

    def record_success(self) -> None:
        # Fix #347: Only transition HALF_OPEN -> CLOSED (not OPEN -> CLOSED directly).
        # Direct OPEN -> CLOSED would skip the recovery probe window.
        with self._lock:
            if self._state in (CircuitState.HALF_OPEN, CircuitState.CLOSED):
                self._failure_count = 0
                self._state = CircuitState.CLOSED
                self._cached_state = CircuitState.CLOSED
                self._cached_state_time = time.time()

    def record_failure(self) -> None:
        with self._lock:
            self._failure_count += 1
            self._last_failure_time = time.time()
            if self._failure_count >= self.failure_threshold:
                self._state = CircuitState.OPEN
                self._cached_state = CircuitState.OPEN
                self._cached_state_time = time.time()
                logger.warning(
                    "Circuit breaker OPEN: %d consecutive failures",
                    self._failure_count,
                )

    def can_execute(self) -> bool:
        return self.state != CircuitState.OPEN
