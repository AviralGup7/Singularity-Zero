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

import threading
from importlib import import_module
from typing import Any

# ---------------------------------------------------------------------------
# Module self-description
# ---------------------------------------------------------------------------

MODULE_META: dict[str, Any] = {
    "name": "learning",
    "version": "3.1.0",
    "description": (
        "ML-backed feedback loops, finding deduplication, baseline "
        "tracking, and telemetry repositories for closed-loop severity "
        "calibration and false-positive suppression."
    ),
    "layer": "learning",
    "submodules": (
        "config",
        "integration",
        "models",
        "repositories",
    ),
    "public_api": (
        "TelemetryStore",
        "LearningConfig",
        "FeedbackLoopEngine",
        "ScanAdaptation",
        "FPTracker",
        "ThresholdTuner",
        "MetricsCollector",
    ),
    "depends_on": ("core", "analysis", "intelligence"),
    "entry_points": (),
    "health_check": "health_check",
}


def health_check() -> dict[str, Any]:
    """Verify learning subsystem health.

    Returns:
        Dict with ``status`` (``"ok"`` / ``"degraded"``), ``module``,
        ``version``, and optional ``errors``.
    """
    try:
        from src.learning.feedback_loop import FeedbackLoopEngine  # noqa: F401
        from src.learning.telemetry_store import TelemetryStore  # noqa: F401

        return {
            "status": "ok",
            "module": "learning",
            "version": "3.1.0",
            "details": {
                "telemetry_store": "available",
                "feedback_loop": "available",
            },
        }
    except ImportError as exc:
        return {
            "status": "degraded",
            "module": "learning",
            "version": "3.1.0",
            "errors": [str(exc)],
        }


# ---------------------------------------------------------------------------
# Register self in the global module registry
# ---------------------------------------------------------------------------

from src.core.utils.shared import register_module_meta  # noqa: E402

register_module_meta(MODULE_META)

# ---------------------------------------------------------------------------
# Lazy facade (unchanged)
# ---------------------------------------------------------------------------

_LAZY_CACHE: dict[str, Any] = {}
_LAZY_CACHE_LOCK = threading.Lock()

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
    "SignalQualityResult": "src.learning.signal_quality",
    "GoldenSetEvaluation": "src.learning.signal_quality",
    "score_signal_quality": "src.learning.signal_quality",
    "annotate_signal_quality": "src.learning.signal_quality",
    "evaluate_golden_set": "src.learning.signal_quality",
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
    # Signal quality
    "SignalQualityResult",
    "GoldenSetEvaluation",
    "score_signal_quality",
    "annotate_signal_quality",
    "evaluate_golden_set",
]


def __getattr__(name: str) -> Any:
    module_path = _EXPORTS.get(name)
    if module_path is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module = import_module(module_path)
    value = getattr(module, name)
    with _LAZY_CACHE_LOCK:
        _LAZY_CACHE[name] = value
    return value


def clear_lazy_cache() -> None:
    """Clear the lazy import cache.

    This is primarily intended for test teardown so that monkeypatches
    to underlying modules are visible on the next access.
    """
    with _LAZY_CACHE_LOCK:
        _LAZY_CACHE.clear()
