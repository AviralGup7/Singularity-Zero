"""Self-improving learning subsystem for the vulnerability scanning pipeline.

Provides closed-loop feedback, adaptive risk-ranking, FP tracking,
threshold auto-tuning, and metrics collection.

Usage:
    from learning import TelemetryStore, FeedbackLoopEngine, FPTracker
    from learning import ThresholdTuner, MetricsCollector
    from src.learning.config import LearningConfig

    config = LearningConfig.from_dict({...})
    store = TelemetryStore(config.db_path)
    store.initialize()

    feedback = FeedbackLoopEngine(store)
    adaptations = feedback.compute_adaptations(target="example.com")

    fp_tracker = FPTracker(store)
    await fp_tracker.update_from_run(run_id)

    tuner = ThresholdTuner(store)
    new_thresholds = tuner.calibrate(run_id)

    metrics = MetricsCollector(store)
    kpis = metrics.compute_kpis()
"""

from __future__ import annotations

from importlib import import_module
from typing import Any

_EXPORTS: dict[str, str] = {
    "TelemetryStore": "src.learning.telemetry_store",
    "LearningConfig": "src.learning.config",
    "FeedbackLoopEngine": "src.learning.feedback_loop",
    "ScanAdaptation": "src.learning.feedback_loop",
    "ExploitTarget": "src.learning.feedback_loop",
    "FPTracker": "src.learning.fp_tracker",
    "ThresholdTuner": "src.learning.threshold_tuner",
    "ThresholdConfig": "src.learning.threshold_tuner",
    "ThresholdUpdate": "src.learning.threshold_tuner",
    "MetricsCollector": "src.learning.metrics",
    "PipelineKPIs": "src.learning.metrics",
}

__all__ = [
    # Core
    "TelemetryStore",
    "LearningConfig",
    # Feedback
    "FeedbackLoopEngine",
    "ScanAdaptation",
    "ExploitTarget",
    # FP Tracking
    "FPTracker",
    # Threshold Tuning
    "ThresholdTuner",
    "ThresholdConfig",
    "ThresholdUpdate",
    # Metrics
    "MetricsCollector",
    "PipelineKPIs",
]


def __getattr__(name: str) -> Any:
    module_path = _EXPORTS.get(name)
    if module_path is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module = import_module(module_path)
    value = getattr(module, name)
    globals()[name] = value
    return value
