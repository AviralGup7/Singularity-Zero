"""Feature flags for the dashboard.

All public accessors are exposed in two equivalent forms:

  * PEP-8 snake_case methods (``enable_sse_progress()``)
  * UPPER_CASE class-method aliases (``ENABLE_SSE_PROGRESS()``)

Both call into the same single-source-of-truth helper so behaviour is
identical regardless of which style a caller prefers. Legacy code that
imports the UPPER_CASE names keeps working; new code should prefer
the snake_case methods.
"""

import os

_FLAG_BOOL_NAMES: tuple[str, ...] = (
    "ENABLE_SSE_PROGRESS",
    "ENABLE_BAYESIAN_ETA",
    "ENABLE_PLUGIN_PROGRESS",
    "ENABLE_DURATION_FORECAST",
    "ENABLE_FINDINGS_STREAM",
    "ENABLE_DAG_EXECUTION",
    "ENABLE_API_SECURITY",
)


def _read_bool(name: str, default: str = "true") -> bool:
    return os.getenv(name, default).lower() == "true"


class FeatureFlags:
    """Feature flags for the dashboard.

    Values are read dynamically from environment variables on first access.
    Runtime env var changes are picked up without restart (lazy evaluation).
    """

    @classmethod
    def _bool_flag(cls, name: str) -> bool:
        return _read_bool(name, "true")

    @classmethod
    def enable_sse_progress(cls) -> bool:
        return cls._bool_flag("ENABLE_SSE_PROGRESS")

    @classmethod
    def enable_bayesian_eta(cls) -> bool:
        return cls._bool_flag("ENABLE_BAYESIAN_ETA")

    @classmethod
    def enable_plugin_progress(cls) -> bool:
        return cls._bool_flag("ENABLE_PLUGIN_PROGRESS")

    @classmethod
    def enable_duration_forecast(cls) -> bool:
        return cls._bool_flag("ENABLE_DURATION_FORECAST")

    @classmethod
    def enable_findings_stream(cls) -> bool:
        return cls._bool_flag("ENABLE_FINDINGS_STREAM")

    @classmethod
    def enable_dag_execution(cls) -> bool:
        return cls._bool_flag("ENABLE_DAG_EXECUTION")

    @classmethod
    def enable_api_security(cls) -> bool:
        return cls._bool_flag("ENABLE_API_SECURITY")

    @classmethod
    def sse_heartbeat_interval_seconds(cls) -> int:
        return max(15, min(30, int(os.getenv("SSE_HEARTBEAT_INTERVAL_SECONDS", "25"))))

    @classmethod
    def eta_engine_background_interval_seconds(cls) -> int:
        return max(1, int(os.getenv("ETA_ENGINE_BACKGROUND_INTERVAL_SECONDS", "5")))

    @classmethod
    def eta_historical_data_path(cls) -> str:
        return os.getenv("ETA_HISTORICAL_DATA_PATH", "output/eta_history.json")

    @classmethod
    def stalled_threshold_seconds(cls) -> int:
        return max(1, int(os.getenv("STALLED_THRESHOLD_SECONDS", "120")))

    @classmethod
    def __getattr__(cls, name: str):  # pragma: no cover - dispatch only
        if name in _FLAG_BOOL_NAMES:
            return classmethod(lambda cls, n=name: cls._bool_flag(n))
        raise AttributeError(f"FeatureFlags has no attribute {name!r}")
        return os.getenv("ETA_HISTORICAL_DATA_PATH", "output/eta_history.json")

    @classmethod
    def sse_max_findings_per_batch(cls) -> int:
        return max(1, int(os.getenv("SSE_MAX_FINDINGS_PER_BATCH", "50")))

    @classmethod
    def stalled_threshold_seconds(cls) -> int:
        return int(os.getenv("STALLED_THRESHOLD_SECONDS", "75"))

    @classmethod
    def job_cleanup_age_days(cls) -> int:
        return int(os.getenv("JOB_CLEANUP_AGE_DAYS", "30"))


# Backwards-compatible UPPER_SNAKE_CASE aliases for legacy callers.
FeatureFlags.ENABLE_SSE_PROGRESS = FeatureFlags.enable_sse_progress  # type: ignore[attr-defined]
FeatureFlags.ENABLE_BAYESIAN_ETA = FeatureFlags.enable_bayesian_eta  # type: ignore[attr-defined]
FeatureFlags.ENABLE_PLUGIN_PROGRESS = FeatureFlags.enable_plugin_progress  # type: ignore[attr-defined]
FeatureFlags.ENABLE_DURATION_FORECAST = FeatureFlags.enable_duration_forecast  # type: ignore[attr-defined]
FeatureFlags.ENABLE_FINDINGS_STREAM = FeatureFlags.enable_findings_stream  # type: ignore[attr-defined]
FeatureFlags.ENABLE_DAG_EXECUTION = FeatureFlags.enable_dag_execution  # type: ignore[attr-defined]
FeatureFlags.ENABLE_API_SECURITY = FeatureFlags.enable_api_security  # type: ignore[attr-defined]
FeatureFlags.SSE_HEARTBEAT_INTERVAL_SECONDS = FeatureFlags.sse_heartbeat_interval_seconds  # type: ignore[attr-defined]
FeatureFlags.ETA_ENGINE_BACKGROUND_INTERVAL_SECONDS = FeatureFlags.eta_engine_background_interval_seconds  # type: ignore[attr-defined]
FeatureFlags.ETA_HISTORICAL_DATA_PATH = FeatureFlags.eta_historical_data_path  # type: ignore[attr-defined]
FeatureFlags.SSE_MAX_FINDINGS_PER_BATCH = FeatureFlags.sse_max_findings_per_batch  # type: ignore[attr-defined]
FeatureFlags.STALLED_THRESHOLD_SECONDS = FeatureFlags.stalled_threshold_seconds  # type: ignore[attr-defined]
FeatureFlags.JOB_CLEANUP_AGE_DAYS = FeatureFlags.job_cleanup_age_days  # type: ignore[attr-defined]
