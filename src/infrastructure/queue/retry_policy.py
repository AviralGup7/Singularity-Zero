"""Configurable retry policy with exponential backoff and jitter.

Provides the RetryPolicy class which calculates retry delays for failed jobs.
"""

from __future__ import annotations


class RetryPolicy:
    """Configurable retry policy with exponential backoff.

    Attributes:
        max_retries: Maximum number of retry attempts.
        backoff_multiplier: Multiplier for exponential backoff calculation.
        initial_delay: Initial delay in seconds before first retry.
        max_delay: Maximum delay in seconds between retries.
        jitter: Whether to add random jitter to backoff delays.
    """

    def __init__(
        self,
        max_retries: int = 3,
        backoff_multiplier: float = 2.0,
        initial_delay: float = 1.0,
        max_delay: float = 300.0,
        jitter: bool = True,
    ) -> None:
        """Initialize the retry policy.

        Args:
            max_retries: Maximum retry attempts before dead-lettering.
            backoff_multiplier: Exponential backoff multiplier.
            initial_delay: Initial delay in seconds.
            max_delay: Maximum delay cap in seconds.
            jitter: Whether to add random jitter (prevents thundering herd).
        """
        self.max_retries = max_retries
        self.backoff_multiplier = backoff_multiplier
        self.initial_delay = initial_delay
        self.max_delay = max_delay
        self.jitter = jitter

    def get_delay(self, attempt: int) -> float:
        """Calculate the delay before the next retry attempt.

        Uses exponential backoff with optional jitter.

        Args:
            attempt: The current retry attempt number (0-indexed).

        Returns:
            Delay in seconds before the next retry.
        """
        delay = self.initial_delay * (self.backoff_multiplier**attempt)
        delay = min(delay, self.max_delay)

        if self.jitter:
            import secrets

            # Use randbelow to prevent thundering herd
            delay = delay * (0.5 + secrets.randbelow(1000) / 2000.0)

        return delay
