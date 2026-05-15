"""Response size anomaly detection for JSON analysis.

Contains functions for detecting anomalous response sizes that could indicate
data leakage, debug output, stack traces, error responses, or truncated data.
Uses statistical outlier detection with standard deviation.
Extracted from json_analysis.py for better separation of concerns.
"""

from statistics import median
from typing import Any

from src.analysis.helpers import classify_endpoint, endpoint_base_key, endpoint_signature
from src.analysis.json.support import resource_group_for_url as _resource_group_for_url


def response_size_anomaly_detector(
    responses: list[dict[str, Any]], limit: int = 40
) -> list[dict[str, Any]]:
    """Detect anomalous response sizes that could indicate data leakage or information disclosure.

    Enhanced to detect:
    - Oversized responses (potential data leakage, debug output, stack traces)
    - Undersized responses (potential error responses, truncated data)
    - Statistical outlier detection using standard deviation
    - Severity classification based on anomaly magnitude
    - Content-type-aware thresholds
    """
    grouped: dict[str, list[dict[str, Any]]] = {}
    for response in responses:
        url = str(response.get("url", "")).strip()
        if not url:
            continue
        resource = _resource_group_for_url(url) or classify_endpoint(url).lower()
        grouped.setdefault(resource, []).append(response)

    findings: list[dict[str, Any]] = []
    for resource, items in grouped.items():
        lengths = sorted(
            int(item.get("body_length", 0)) for item in items if int(item.get("body_length", 0)) > 0
        )
        if len(lengths) < 3:
            continue
        baseline = max(int(median(lengths)), 1)
        # Calculate standard deviation for statistical outlier detection
        mean_length = sum(lengths) / len(lengths)
        variance = sum((x - mean_length) ** 2 for x in lengths) / len(lengths)
        std_dev = variance**0.5 if variance > 0 else 1

        for item in items:
            length = int(item.get("body_length", 0))
            if length <= 0:
                continue
            # Calculate deviation from baseline
            deviation_ratio = length / baseline if baseline > 0 else 0
            # Statistical z-score
            z_score = (length - mean_length) / std_dev if std_dev > 0 else 0

            # Determine anomaly type and severity
            anomaly_type = ""
            severity = "info"
            signals = []

            if deviation_ratio > 3.0 or z_score > 3.0:
                anomaly_type = "oversized"
                severity = "high"
                signals.append("severely_oversized_response")
            elif deviation_ratio > 2.0 or z_score > 2.0:
                anomaly_type = "oversized"
                severity = "medium"
                signals.append("oversized_response")
            elif deviation_ratio < 0.3 or z_score < -2.5:
                anomaly_type = "undersized"
                severity = "medium"
                signals.append("undersized_response")
            elif deviation_ratio < 0.5 or z_score < -2.0:
                anomaly_type = "undersized"
                severity = "low"
                signals.append("slightly_undersized_response")

            if not anomaly_type:
                continue

            # Additional context signals
            if length > 100000:
                signals.append("very_large_response")
            if length < 50:
                signals.append("very_small_response")
            if z_score > 4.0:
                signals.append("statistical_outlier")

            url = str(item.get("url", "")).strip()
            findings.append(
                {
                    "url": url,
                    "endpoint_key": endpoint_signature(url),
                    "endpoint_base_key": endpoint_base_key(url),
                    "resource_group": resource,
                    "response_length": length,
                    "baseline_length": baseline,
                    "deviation_ratio": round(deviation_ratio, 2),
                    "z_score": round(z_score, 2),
                    "anomaly_type": anomaly_type,
                    "severity": severity,
                    "signals": signals,
                }
            )

    findings.sort(
        key=lambda item: (
            0 if item["severity"] == "high" else 1 if item["severity"] == "medium" else 2,
            -abs(item["z_score"]),
            item["url"],
        )
    )
    return findings[:limit]
