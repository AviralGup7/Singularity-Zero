"""Behavioral baseline tracking for the learning pipeline.

Tracks baseline metrics across pipeline runs to detect anomalies:
- Finding rate per subdomain
- False positive rate trends
- Recon coverage percentage
- Tool reliability rates
- Response time distributions
- Severity distribution drift

Enables the learning system to detect when results are anomalous
vs. expected based on historical data.
"""

import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class RunBaseline:
    """Snapshot of a single pipeline run's baseline metrics."""

    run_id: str
    timestamp: float
    scope_size: int
    subdomains_found: int
    live_hosts_found: int
    urls_found: int
    parameters_found: int
    total_findings: int
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    info_findings: int
    false_positive_rate: float
    avg_confidence: float
    tool_success_rate: float
    recon_coverage_percent: float
    scan_duration_seconds: float
    findings_per_subdomain: float
    checksum: str = ""

    def __post_init__(self) -> None:
        if not self.checksum:
            self.checksum = self._compute_checksum()

    def _compute_checksum(self) -> str:
        """Compute a checksum for this baseline to detect tampering."""
        parts = [
            self.run_id,
            str(self.timestamp),
            str(self.total_findings),
            str(self.critical_findings),
            str(self.high_findings),
            str(self.scope_size),
            str(self.subdomains_found),
        ]
        return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:16]


@dataclass
class BaselineTracker:
    """Tracks baselines across runs and computes anomaly scores."""

    _baselines: list[RunBaseline] = field(default_factory=list)
    _storage_path: Path | None = None
    _window_size: int = 10

    def add(self, baseline: RunBaseline) -> None:
        """Add a new baseline snapshot."""
        self._baselines.append(baseline)
        self._baselines.sort(key=lambda b: b.timestamp)
        if len(self._baselines) > self._window_size:
            self._baselines = self._baselines[-self._window_size :]
        self._persist()

    def compute_anomaly_score(self, current: RunBaseline) -> dict[str, Any]:
        """Compare current metrics against historical baselines.

        Returns:
            Dict with anomaly_score (0-1), anomalies list, and per-metric deviations.
        """
        if len(self._baselines) < 2:
            return {
                "anomaly_score": 0.0,
                "anomalies": [],
                "message": "Insufficient historical data for baseline comparison",
            }

        recent = self._baselines[-self._window_size :]
        anomalies: list[dict[str, Any]] = []

        metrics = [
            ("total_findings", 2.0, "high"),
            ("critical_findings", 3.0, "critical"),
            ("false_positive_rate", 0.3, "medium"),
            ("avg_confidence", 0.15, "medium"),
            ("recon_coverage_percent", 0.25, "low"),
            ("findings_per_subdomain", 2.0, "medium"),
            ("scan_duration_seconds", 3.0, "low"),
        ]

        anomaly_score = 0.0

        for attr_name, threshold, severity in metrics:
            values = [getattr(b, attr_name) for b in recent]
            mean = sum(values) / len(values)
            std = (sum((v - mean) ** 2 for v in values) / len(values)) ** 0.5

            if std == 0:
                continue

            current_val = getattr(current, attr_name)
            z_score = abs(current_val - mean) / max(std, 0.001)

            if z_score > threshold:
                anomaly_score += min(z_score / (threshold * 3), 1.0)
                anomalies.append(
                    {
                        "metric": attr_name,
                        "current_value": round(current_val, 4),
                        "historical_mean": round(mean, 4),
                        "historical_std": round(std, 4),
                        "z_score": round(z_score, 2),
                        "severity": severity,
                        "direction": "increased" if current_val > mean else "decreased",
                    }
                )

        anomaly_score = min(anomaly_score / max(len(metrics), 1), 1.0)

        return {
            "anomaly_score": round(anomaly_score, 4),
            "anomalies": anomalies,
            "baseline_count": len(recent),
        }

    def load(self, path: Path) -> None:
        """Load baselines from a JSON file."""
        self._storage_path = path
        if path.exists():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                self._baselines = [RunBaseline(**item) for item in data.get("baselines", [])]
                self._window_size = data.get("window_size", self._window_size)
                logger.info("Loaded %d baselines from %s", len(self._baselines), path)
            except (json.JSONDecodeError, TypeError, KeyError) as exc:
                logger.warning("Failed to load baselines from %s: %s", path, exc)

    def _persist(self) -> None:
        """Save baselines to storage if configured."""
        if self._storage_path is None:
            return
        try:
            self._storage_path.parent.mkdir(parents=True, exist_ok=True)
            data = {
                "baselines": [
                    {k: v for k, v in baseline.__dict__.items()} for baseline in self._baselines
                ],
                "window_size": self._window_size,
            }
            self._storage_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        except OSError as exc:
            logger.warning("Failed to persist baselines: %s", exc)


def compute_baseline_from_run(
    run_id: str,
    pipeline_result: dict[str, Any],
) -> RunBaseline:
    """Compute a baseline snapshot from a completed pipeline run.

    Args:
        run_id: Unique run identifier.
        pipeline_result: Pipeline execution result dictionary.

    Returns:
        RunBaseline with computed metrics.
    """
    metrics = pipeline_result.get("module_metrics", {})
    findings = pipeline_result.get("reportable_findings", [])

    total_findings = len(findings)
    severity_counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }
    confidence_sum = 0.0

    for f in findings:
        sev = str(f.get("severity", "info")).lower()
        if sev in severity_counts:
            severity_counts[sev] += 1
        confidence_sum += float(f.get("confidence", 0))

    avg_confidence = confidence_sum / max(total_findings, 1)
    subdomains = metrics.get("subdomains", {}).get("subdomains_found", 0)
    scope_size = len(pipeline_result.get("scope_entries", []))
    findings_per_subdomain = total_findings / max(subdomains, 1)

    duration = metrics.get("reporting", {}).get("duration_seconds", 0)
    for stage_metrics in metrics.values():
        if isinstance(stage_metrics, dict) and "duration_seconds" in stage_metrics:
            duration += stage_metrics.get("duration_seconds", 0)

    fp_count = sum(1 for f in findings if f.get("decision", "").upper() == "FALSE_POSITIVE")
    fp_rate = fp_count / max(total_findings, 1)

    return RunBaseline(
        run_id=run_id,
        timestamp=time.time(),
        scope_size=scope_size,
        subdomains_found=subdomains,
        live_hosts_found=metrics.get("live_hosts", {}).get("live_hosts_found", 0),
        urls_found=metrics.get("urls", {}).get("urls_found", 0),
        parameters_found=metrics.get("parameters", {}).get("parameters_found", 0),
        total_findings=total_findings,
        critical_findings=severity_counts["critical"],
        high_findings=severity_counts["high"],
        medium_findings=severity_counts["medium"],
        low_findings=severity_counts["low"],
        info_findings=severity_counts["info"],
        false_positive_rate=round(fp_rate, 4),
        avg_confidence=round(avg_confidence, 4),
        tool_success_rate=pipeline_result.get("tool_success_rate", 1.0),
        recon_coverage_percent=pipeline_result.get("recon_coverage_percent", 100.0),
        scan_duration_seconds=round(duration, 2),
        findings_per_subdomain=round(findings_per_subdomain, 4),
    )
