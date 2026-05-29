"""Real-time statistical anomaly detection engine for pipeline metrics.

Calculates rolling averages and standard deviations to trigger active auto-throttling.
"""

from __future__ import annotations

import logging
import math
from typing import Any

logger = logging.getLogger(__name__)


class ScanAnomalyDetector:
    """Detects statistical outliers in scan latency and response patterns to trigger auto-throttling."""

    def __init__(self, history_limit: int = 100) -> None:
        self.history_limit = history_limit
        self._latencies: list[float] = []
        self._response_sizes: list[int] = []

    def record_metrics(self, latency_seconds: float, response_size_bytes: int) -> None:
        """Record real-time execution statistics to sliding window buffers."""
        self._latencies.append(latency_seconds)
        self._response_sizes.append(response_size_bytes)

        # Enforce sliding history bounds
        if len(self._latencies) > self.history_limit:
            self._latencies.pop(0)
        if len(self._response_sizes) > self.history_limit:
            self._response_sizes.pop(0)

    def _stats(self, values: list[float] | list[int]) -> tuple[float, float]:
        """Calculate mean and standard deviation of values."""
        if len(values) < 2:
            return 0.0, 0.0
        mean = sum(values) / len(values)
        variance = sum((x - mean) ** 2 for x in values) / (len(values) - 1)
        return mean, math.sqrt(variance)

    def analyze_latency_anomaly(self, current_latency: float) -> dict[str, Any]:
        """Perform standard deviation outlier check for a given request latency.

        If the current latency exceeds 3 standard deviations (3-sigma) above
        the moving average, it is flagged as an ANOMALY.
        """
        if len(self._latencies) < 5:
            # Insufficient baseline data
            return {"anomaly": False, "z_score": 0.0, "status": "insufficient_data"}

        mean, std_dev = self._stats(self._latencies)
        if std_dev == 0.0:
            return {"anomaly": False, "z_score": 0.0, "status": "stable"}

        z_score = (current_latency - mean) / std_dev
        is_anomaly = z_score > 3.0

        return {
            "anomaly": is_anomaly,
            "z_score": round(z_score, 2),
            "mean": round(mean, 4),
            "std_dev": round(std_dev, 4),
            "current": round(current_latency, 4),
            "status": "ANOMALOUS_SPIKE" if is_anomaly else "NORMAL",
        }

    def should_throttle(self, current_latency: float) -> bool:
        """Determine if active execution threads should throttle to prevent node starvation."""
        analysis = self.analyze_latency_anomaly(current_latency)
        if analysis.get("anomaly"):
            logger.warning(
                "Anomaly detection: Latency spike detected (Z-Score: %s). Auto-throttling active.",
                analysis.get("z_score"),
            )
            return True
        return False
