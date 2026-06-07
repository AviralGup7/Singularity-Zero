"""Timing-based SQL injection detection using Welch's t-test."""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class TimingComparator:
    """Compare response timing distributions using Welch's t-test.

    Compares payload response times against baseline response times
    to detect timing-based blind SQL injection without external
    dependencies (no scipy).
    """

    _payload_times: list[float] = field(default_factory=list, repr=False)
    _baseline_times: list[float] = field(default_factory=list, repr=False)

    def compare(
        self,
        payload_responses: list[dict[str, Any]],
        baseline_responses: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Compare two response sets using Welch's t-test.

        Args:
            payload_responses: Responses to SQLi payloads.
            baseline_responses: Baseline normal responses.

        Returns:
            Dict with t-statistic, degrees of freedom, p-value, and means.
        """
        payload_times = [
            float(r.get("response_time_ms", 0) or 0) for r in payload_responses if r
        ]
        baseline_times = [
            float(r.get("response_time_ms", 0) or 0) for r in baseline_responses if r
        ]

        self._payload_times = payload_times
        self._baseline_times = baseline_times

        n1 = len(payload_times)
        n2 = len(baseline_times)

        if n1 == 0 or n2 == 0:
            return {
                "t_statistic": 0.0,
                "degrees_of_freedom": 0.0,
                "p_value": 1.0,
                "significant": False,
                "payload_mean_ms": 0.0,
                "baseline_mean_ms": 0.0,
                "payload_variance": 0.0,
                "baseline_variance": 0.0,
            }

        mean1 = sum(payload_times) / n1
        mean2 = sum(baseline_times) / n2

        var1 = sum((t - mean1) ** 2 for t in payload_times) / (n1 - 1) if n1 > 1 else 0.0
        var2 = sum((t - mean2) ** 2 for t in baseline_times) / (n2 - 1) if n2 > 1 else 0.0

        se = math.sqrt(var1 / n1 + var2 / n2)
        if se == 0:
            return {
                "t_statistic": 0.0,
                "degrees_of_freedom": float(n1 + n2 - 2),
                "p_value": 1.0,
                "significant": False,
                "payload_mean_ms": mean1,
                "baseline_mean_ms": mean2,
                "payload_variance": var1,
                "baseline_variance": var2,
            }

        t_stat = (mean1 - mean2) / se

        numerator = (var1 / n1 + var2 / n2) ** 2
        denominator = (var1 / n1) ** 2 / (n1 - 1) + (var2 / n2) ** 2 / (n2 - 1)
        df = numerator / denominator if denominator != 0 else float(n1 + n2 - 2)

        p_value = self._t_cdf_survival(abs(t_stat), df) * 2.0
        p_value = max(0.0, min(1.0, p_value))

        return {
            "t_statistic": t_stat,
            "degrees_of_freedom": df,
            "p_value": p_value,
            "significant": p_value < 0.01,
            "payload_mean_ms": mean1,
            "baseline_mean_ms": mean2,
            "payload_variance": var1,
            "baseline_variance": var2,
        }

    def detect_anomaly(self, p_value_threshold: float = 0.01) -> dict[str, Any]:
        """Report whether a timing anomaly is detected.

        Args:
            p_value_threshold: Significance level (default 0.01).

        Returns:
            Dict with anomaly detection result and timing stats.
        """
        if not self._payload_times or not self._baseline_times:
            return {
                "anomaly_detected": False,
                "reason": "insufficient_data",
                "p_value": 1.0,
                "threshold": p_value_threshold,
            }

        result = self.compare(
            [{"response_time_ms": t} for t in self._payload_times],
            [{"response_time_ms": t} for t in self._baseline_times],
        )
        significant = result["p_value"] < p_value_threshold

        mean_delta = result["payload_mean_ms"] - result["baseline_mean_ms"]

        return {
            "anomaly_detected": significant,
            "reason": "timing_anomaly" if significant else "no_significant_timing_difference",
            "p_value": result["p_value"],
            "threshold": p_value_threshold,
            "t_statistic": result["t_statistic"],
            "degrees_of_freedom": result["degrees_of_freedom"],
            "payload_mean_ms": result["payload_mean_ms"],
            "baseline_mean_ms": result["baseline_mean_ms"],
            "mean_delta_ms": mean_delta,
            "payload_variance": result["payload_variance"],
            "baseline_variance": result["baseline_variance"],
            "payload_samples": len(self._payload_times),
            "baseline_samples": len(self._baseline_times),
        }

    @staticmethod
    def _log_beta(a: float, b: float) -> float:
        """Compute log(B(a, b)) = log(gamma(a)) + log(gamma(b)) - log(gamma(a+b))."""
        return math.lgamma(a) + math.lgamma(b) - math.lgamma(a + b)

    @staticmethod
    def _betainc_continued_fraction(
        x: float,
        a: float,
        b: float,
        max_iter: int = 200,
        tol: float = 1e-12,
    ) -> float:
        """Compute the regularized incomplete beta function I_x(a, b).

        Uses the continued fraction representation with Lentz's method
        for numerical stability.
        """
        if x < 0.0 or x > 1.0:
            raise ValueError("x must be in [0, 1]")
        if x == 0.0:
            return 0.0
        if x == 1.0:
            return 1.0

        lbeta_ab = TimingComparator._log_beta(a, b)
        front = math.exp(
            a * math.log(x) + b * math.log(1.0 - x) - lbeta_ab
        )

        if x < (a + 1.0) / (a + b + 2.0):
            return front * TimingComparator._betainc_cf(x, a, b, max_iter, tol)
        else:
            return 1.0 - front * TimingComparator._betainc_cf(
                1.0 - x, b, a, max_iter, tol
            )

    @staticmethod
    def _betainc_cf(
        x: float,
        a: float,
        b: float,
        max_iter: int,
        tol: float,
    ) -> float:
        """Evaluate the continued fraction for betainc using Lentz's method."""
        qab = a + b
        qap = a + 1.0
        qam = a - 1.0
        c = 1.0
        d = 1.0 - qab * x / qap
        if abs(d) < 1e-30:
            d = 1e-30
        d = 1.0 / d
        h = d

        for m in range(1, max_iter + 1):
            m2 = 2 * m
            aa = m * (b - m) * x / ((qam + m2) * (a + m2))
            d = 1.0 + aa * d
            if abs(d) < 1e-30:
                d = 1e-30
            c = 1.0 + aa / c
            if abs(c) < 1e-30:
                c = 1e-30
            d = 1.0 / d
            h *= d * c

            aa = -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2))
            d = 1.0 + aa * d
            if abs(d) < 1e-30:
                d = 1e-30
            c = 1.0 + aa / c
            if abs(c) < 1e-30:
                c = 1e-30
            d = 1.0 / d
            delta = d * c
            h *= delta

            if abs(delta - 1.0) < tol:
                break

        return h

    @staticmethod
    def _t_cdf_survival(t_val: float, df: float) -> float:
        """Compute the upper-tail probability of the t-distribution: P(T > t).

        Uses the relationship to the regularized incomplete beta function:
        P(T > t) = 0.5 * I(df/(df+t^2), df/2, 1/2)
        """
        x = df / (df + t_val * t_val)
        ibeta = TimingComparator._betainc_continued_fraction(x, df / 2.0, 0.5)
        return 0.5 * ibeta

    @staticmethod
    def welch_t_test(
        sample_a: list[float],
        sample_b: list[float],
    ) -> dict[str, Any]:
        """Run Welch's t-test on two samples of response times.

        Args:
            sample_a: First sample (e.g. payload response times in ms).
            sample_b: Second sample (e.g. baseline response times in ms).

        Returns:
            Dict with t-statistic, df, p-value, and significance.
        """
        comparator = TimingComparator()
        responses_a = [{"response_time_ms": t} for t in sample_a]
        responses_b = [{"response_time_ms": t} for t in sample_b]
        result = comparator.compare(responses_a, responses_b)
        result["significant"] = result["p_value"] < 0.01
        return result
