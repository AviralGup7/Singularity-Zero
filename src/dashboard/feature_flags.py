"""Feature flags for the dashboard."""

import os


class FeatureFlags:
    """Feature flags for the dashboard.

    Values are read dynamically from environment variables on first access.
    Runtime env var changes are picked up without restart (lazy evaluation).
    """

    @classmethod
    def enable_sse_progress(cls) -> bool:
        return os.getenv("ENABLE_SSE_PROGRESS", "true").lower() == "true"

    @classmethod
    def ENABLE_SSE_PROGRESS(cls) -> bool:  # noqa: N802
        return cls.enable_sse_progress()

    @classmethod
    def enable_bayesian_eta(cls) -> bool:
        return os.getenv("ENABLE_BAYESIAN_ETA", "true").lower() == "true"

    @classmethod
    def ENABLE_BAYESIAN_ETA(cls) -> bool:  # noqa: N802
        return cls.enable_bayesian_eta()

    @classmethod
    def enable_plugin_progress(cls) -> bool:
        return os.getenv("ENABLE_PLUGIN_PROGRESS", "true").lower() == "true"

    @classmethod
    def ENABLE_PLUGIN_PROGRESS(cls) -> bool:  # noqa: N802
        return cls.enable_plugin_progress()

    @classmethod
    def enable_duration_forecast(cls) -> bool:
        return os.getenv("ENABLE_DURATION_FORECAST", "true").lower() == "true"

    @classmethod
    def ENABLE_DURATION_FORECAST(cls) -> bool:  # noqa: N802
        return cls.enable_duration_forecast()

    @classmethod
    def enable_findings_stream(cls) -> bool:
        return os.getenv("ENABLE_FINDINGS_STREAM", "true").lower() == "true"

    @classmethod
    def ENABLE_FINDINGS_STREAM(cls) -> bool:  # noqa: N802
        return cls.enable_findings_stream()

    @classmethod
    def enable_dag_execution(cls) -> bool:
        return os.getenv("ENABLE_DAG_EXECUTION", "true").lower() == "true"

    @classmethod
    def ENABLE_DAG_EXECUTION(cls) -> bool:  # noqa: N802
        return cls.enable_dag_execution()

    @classmethod
    def enable_api_security(cls) -> bool:
        return os.getenv("ENABLE_API_SECURITY", "true").lower() == "true"

    @classmethod
    def ENABLE_API_SECURITY(cls) -> bool:  # noqa: N802
        return cls.enable_api_security()

    @classmethod
    def sse_heartbeat_interval_seconds(cls) -> int:
        return max(15, min(30, int(os.getenv("SSE_HEARTBEAT_INTERVAL_SECONDS", "25"))))

    @classmethod
    def SSE_HEARTBEAT_INTERVAL_SECONDS(cls) -> int:  # noqa: N802
        return cls.sse_heartbeat_interval_seconds()

    @classmethod
    def eta_engine_background_interval_seconds(cls) -> int:
        return max(1, int(os.getenv("ETA_ENGINE_BACKGROUND_INTERVAL_SECONDS", "5")))

    @classmethod
    def ETA_ENGINE_BACKGROUND_INTERVAL_SECONDS(cls) -> int:  # noqa: N802
        return cls.eta_engine_background_interval_seconds()

    @classmethod
    def eta_historical_data_path(cls) -> str:
        return os.getenv("ETA_HISTORICAL_DATA_PATH", "output/eta_history.json")

    @classmethod
    def ETA_HISTORICAL_DATA_PATH(cls) -> str:  # noqa: N802
        return cls.eta_historical_data_path()

    @classmethod
    def sse_max_findings_per_batch(cls) -> int:
        return max(1, int(os.getenv("SSE_MAX_FINDINGS_PER_BATCH", "50")))

    @classmethod
    def SSE_MAX_FINDINGS_PER_BATCH(cls) -> int:  # noqa: N802
        return cls.sse_max_findings_per_batch()

    @classmethod
    def stalled_threshold_seconds(cls) -> int:
        return int(os.getenv("STALLED_THRESHOLD_SECONDS", "75"))

    @classmethod
    def STALLED_THRESHOLD_SECONDS(cls) -> int:  # noqa: N802
        return cls.stalled_threshold_seconds()

    @classmethod
    def job_cleanup_age_days(cls) -> int:
        return int(os.getenv("JOB_CLEANUP_AGE_DAYS", "30"))

    @classmethod
    def JOB_CLEANUP_AGE_DAYS(cls) -> int:  # noqa: N802
        return cls.job_cleanup_age_days()
