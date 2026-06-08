"""Statistical timing baseline for latency-based probes."""

from __future__ import annotations

import logging
import math
import statistics
from collections.abc import Sequence

logger = logging.getLogger(__name__)


class TimingComparator:
    """Statistically compare payload response times against a baseline.

    Implements:
    - Welch's t-test (no scipy).
    - Grubbs outlier detection.
    - Confidence interval estimation.
    - Anomalous classification.
    - Adaptive baseline updates.
    """

    def __init__(
        self,
        baseline_responses: Sequence[float],
        payload_responses: Sequence[float],
    ) -> None:
        self.baseline: list[float] = [float(v) for v in baseline_responses]
        self.payload: list[float] = [float(v) for v in payload_responses]
        self._baseline_mean = statistics.mean(self.baseline) if self.baseline else 0.0
        self._baseline_std = statistics.pstdev(self.baseline) if len(self.baseline) > 0 else 0.0
        self._payload_mean = statistics.mean(self.payload) if self.payload else 0.0
        self._payload_std = statistics.pstdev(self.payload) if len(self.payload) > 0 else 0.0
        self._grubbs_outliers: list[float] = []

    def welchs_t_test(self) -> float:
        """Return two-tailed p-value from Welch's t-test."""
        n1, n2 = len(self.baseline), len(self.payload)
        if n1 < 2 or n2 < 2:
            return 1.0
        mean1, mean2 = self._baseline_mean, self._payload_mean
        var1 = self._baseline_std ** 2
        var2 = self._payload_std ** 2
        if var1 == 0 and var2 == 0:
            return 1.0 if mean1 == mean2 else 0.0
        se = math.sqrt(var1 / n1 + var2 / n2)
        if se == 0:
            return 1.0
        t_stat = abs(mean1 - mean2) / se
        num = (var1 / n1 + var2 / n2) ** 2
        denom = (var1 / n1) ** 2 / (n1 - 1) + (var2 / n2) ** 2 / (n2 - 1)
        df = num / denom if denom != 0 else 1.0
        return self._t_cdf_two_tail(t_stat, df)

    @staticmethod
    def _t_cdf_two_tail(t: float, df: float) -> float:
        x = df / (df + t * t)
        ib = TimingComparator._betainc(df * 0.5, 0.5, x)
        return max(0.0, min(1.0, ib))

    @staticmethod
    def _betainc(a: float, b: float, x: float) -> float:
        if x <= 0.0:
            return 0.0
        if x >= 1.0:
            return 1.0
        if x > (a + 1.0) / (a + b + 2.0):
            return 1.0 - TimingComparator._betainc(b, a, 1.0 - x)
        ln = math.log
        lbeta = (
            math.lgamma(a) + math.lgamma(b) - math.lgamma(a + b)
        )
        front = math.exp(
            a * ln(x) + b * ln(1.0 - x) - lbeta
        )
        f = 1.0
        c = 1.0
        d = 1.0e-30 if x > 0.0 else 0.0
        m = 0
        for _ in range(200):
            m += 1
            if m % 2 == 1:
                numerator = m * (b - m) * x / ((a + 2.0 * m - 1.0) * (a + 2.0 * m))
                d = 1.0 + numerator * d
                if abs(d) < 1.0e-30:
                    d = 1.0e-30
                c = 1.0 + numerator / c
            else:
                numerator = -(a + m) * (a + b + m) * x / ((a + 2.0 * m - 1.0) * (a + 2.0 * m))
                d = 1.0 + numerator * d
                if abs(d) < 1.0e-30:
                    d = 1.0e-30
                c = 1.0 + numerator / c
            if abs(d) > 1.0e-30:
                d_inv = 1.0 / d
                delta = c * d_inv
                f *= delta
                if abs(delta - 1.0) < 1.0e-8:
                    break
        return front * f

    def grubbs_outlier_test(self, values: Sequence[float]) -> list[float]:
        """Detect outliers in a list of latency values using Grubbs test."""
        vals = [float(v) for v in values]
        n = len(vals)
        if n < 3:
            return []
        outliers = []
        checked = list(vals)
        while True:
            mean = statistics.mean(checked)
            std = statistics.stdev(checked) if len(checked) > 1 else 0.0
            if std == 0:
                break
            g_max = max(abs(v - mean) for v in checked) / std
            t_crit = self._grubbs_critical(n=len(checked), alpha=0.05)
            if g_max > t_crit:
                outlier = max(checked, key=lambda v: abs(v - mean))
                outliers.append(outlier)
                checked.remove(outlier)
                if len(checked) < 3:
                    break
            else:
                break
        self._grubbs_outliers = outliers
        return outliers

    @staticmethod
    def _grubbs_critical(n: int, alpha: float = 0.05) -> float:
        k = n - 2
        if k <= 0:
            return float("inf")
        base = math.sqrt((n - 1.0) / n)
        if alpha <= 0 or alpha >= 1:
            return base
        log_alpha = math.log(alpha / (2.0 * n))
        log_term = -0.5 * log_alpha
        log_sum = log_term + math.log(math.sqrt(math.pi)) - math.lgamma(0.5)
        return base * math.exp(log_sum) / (math.sqrt(2.0 * k))

    def confidence_interval(
        self, confidence: float = 0.95
    ) -> tuple[float, float]:
        """Return (mean - margin, mean + margin) for payload responses."""
        n = len(self.payload)
        if n == 0:
            return (0.0, 0.0)
        mean = self._payload_mean
        if n == 1:
            return (mean, mean)
        std = statistics.stdev(self.payload)
        if std == 0:
            return (mean, mean)
        z = self._z_for_confidence(confidence)
        margin = z * std / math.sqrt(n)
        return (mean - margin, mean + margin)

    @staticmethod
    def _z_for_confidence(confidence: float) -> float:
        z_lookup = {
            0.80: 1.28155,
            0.90: 1.64485,
            0.95: 1.95996,
            0.98: 2.32635,
            0.99: 2.57583,
        }
        closest = min(z_lookup, key=lambda k: abs(k - confidence))
        return z_lookup[closest]

    def is_anomalous(self, p_value_threshold: float = 0.01) -> bool:
        """Return True if payload timing is statistically anomalous."""
        p = self.welchs_t_test()
        return p < p_value_threshold

    def update_baseline(self, new_responses: Sequence[float]) -> None:
        """Adaptively update baseline mean/std with new latency samples."""
        new_floats = [float(v) for v in new_responses]
        self.baseline + new_floats
        self.baseline.extend(new_floats)
        self._baseline_mean = statistics.mean(self.baseline) if self.baseline else 0.0
        self._baseline_std = statistics.pstdev(self.baseline) if len(self.baseline) > 0 else 0.0
        self._payload_mean = statistics.mean(self.payload) if self.payload else 0.0
        self._payload_std = statistics.pstdev(self.payload) if len(self.payload) > 0 else 0.0
        self._grubbs_outliers = []
        logger.info(
            "Updated timing baseline: n=%d mean=%.4f std=%.4f",
            len(self.baseline),
            self._baseline_mean,
            self._baseline_std,
        )
