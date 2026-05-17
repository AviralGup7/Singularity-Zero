"""Bayesian ETA engine with background scheduler.

Reads historical run_summary.json files, computes per-stage Bayesian estimates,
and caches results for fast lookup. Runs entirely in the background.
"""

import asyncio
import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

STAGE_ORDER = [
    "startup",
    "subdomains",
    "live_hosts",
    "urls",
    "parameters",
    "priority",
    "analysis",
    "nuclei",
    "reporting",
    "completed",
]


class BayesianSimpleModel:
    """Simple Bayesian model for per-stage duration estimation.

    Uses a conjugate normal-normal model with a weak prior.
    posterior_mean = (prior_precision * prior_mean + data_precision * sample_mean) / (prior_precision + data_precision)
    """

    def __init__(
        self,
        prior_mean: float = 300.0,
        prior_variance: float = 600.0**2,
        data_variance: float = 300.0**2,
    ) -> None:
        self._prior_mean = prior_mean
        self._prior_precision = 1.0 / prior_variance
        self._data_variance = data_variance
        self._data_precision = 1.0 / data_variance if data_variance > 0 else 0.0
        self._samples: list[float] = []

    def add_sample(self, duration_seconds: float) -> None:
        if duration_seconds > 0:
            self._samples.append(duration_seconds)

    @property
    def sample_mean(self) -> float:
        if not self._samples:
            return self._prior_mean
        return sum(self._samples) / len(self._samples)

    @property
    def posterior_mean(self) -> float:
        if not self._samples:
            return self._prior_mean
        sm = self.sample_mean
        dp = self._data_precision * len(self._samples)
        return (self._prior_precision * self._prior_mean + dp * sm) / (self._prior_precision + dp)

    @property
    def sample_count(self) -> int:
        return len(self._samples)

    def estimate_remaining(
        self, stage_elapsed: float, stage_index: int, total_stages: int
    ) -> float | None:
        if stage_index >= total_stages - 1:
            return 0.0
        remaining_stages = total_stages - 1 - stage_index
        if remaining_stages <= 0:
            return 0.0
        per_stage = max(self.posterior_mean, stage_elapsed / max(stage_index + 1, 1))
        return per_stage * remaining_stages


class ETAEngine:
    """Background ETA engine with per-file error isolation and caching."""

    def __init__(
        self,
        output_dir: str = "output",
        history_path: str | None = None,
        background_interval: int = 5,
    ) -> None:
        self._output_dir = Path(output_dir)
        self._history_path = (
            Path(history_path) if history_path else self._output_dir / "eta_history.json"
        )
        self._background_interval = max(1, background_interval)
        self._models: dict[str, dict[int, BayesianSimpleModel]] = {}
        self._cache: dict[str, dict[str, Any]] = {}
        self._lock = asyncio.Lock()
        self._task: asyncio.Task[None] | None = None
        self._running = False

    async def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._background_loop())
        logger.info("ETA engine started (interval=%ds)", self._background_interval)

    async def stop(self) -> None:
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        logger.info("ETA engine stopped")

    async def _background_loop(self) -> None:
        while self._running:
            try:
                await self._refresh()
            except Exception:
                logger.exception("ETA engine background refresh failed")
            await asyncio.sleep(self._background_interval)

    async def _refresh(self) -> None:
        """Scan output directory for run_summary.json files and update models."""
        stage_models: dict[str, dict[int, BayesianSimpleModel]] = {}

        try:
            job_dirs = [d for d in self._output_dir.iterdir() if d.is_dir()]
        except OSError:
            logger.warning("Cannot read output directory: %s", self._output_dir)
            return

        for job_dir in job_dirs:
            try:
                summary_path = job_dir / "run_summary.json"
                if not summary_path.exists():
                    continue
                self._load_summary_for_job(str(job_dir.name), summary_path, stage_models)
            except Exception:
                logger.debug("Error processing %s (isolated)", job_dir)
                continue

        async with self._lock:
            self._models = stage_models
            self._cache.clear()

    def _load_summary_for_job(
        self,
        job_id: str,
        summary_path: Path,
        stage_models: dict[str, dict[int, BayesianSimpleModel]],
    ) -> None:
        try:
            with open(summary_path, encoding="utf-8") as f:
                summary = json.load(f)
        except OSError, json.JSONDecodeError:
            logger.debug("Cannot read summary: %s", summary_path)
            return

        stage_durations = summary.get("stage_durations", {})
        if not stage_durations:
            return

        for stage_name, duration in stage_durations.items():
            if not isinstance(duration, (int, float)) or duration <= 0:
                continue
            stage_index = STAGE_ORDER.index(stage_name) if stage_name in STAGE_ORDER else -1
            if stage_index < 0:
                continue
            if job_id not in stage_models:
                stage_models[job_id] = {}
            if stage_index not in stage_models[job_id]:
                stage_models[job_id][stage_index] = BayesianSimpleModel()
            stage_models[job_id][stage_index].add_sample(float(duration))

    async def compute_eta(
        self,
        job_id: str,
        stage: str,
        elapsed: float,
    ) -> dict[str, Any] | None:
        """Compute ETA for the given job/stage/elapsed combination.

        Returns a dict with eta_seconds, eta_label, confidence, and method,
        or None if no estimate is available.
        """
        cache_key = f"{job_id}:{stage}:{int(elapsed // 5)}"
        async with self._lock:
            if cache_key in self._cache:
                return self._cache[cache_key]

        stage_index = STAGE_ORDER.index(stage) if stage in STAGE_ORDER else 0
        total_stages = len(STAGE_ORDER)

        model = self._get_aggregate_model(stage_index)
        if model and model.sample_count > 0:
            remaining = model.estimate_remaining(elapsed, stage_index, total_stages)
            if remaining is not None:
                result = {
                    "eta_seconds": round(remaining, 1),
                    "confidence": min(0.95, 0.3 + 0.1 * model.sample_count),
                    "method": "bayesian",
                    "sample_count": model.sample_count,
                }
                async with self._lock:
                    self._cache[cache_key] = result
                return result

        return None

    def compute_eta_sync(
        self,
        job_id: str,
        stage: str,
        elapsed: float,
    ) -> dict[str, Any] | None:
        """Synchronous version of compute_eta for use outside async context."""

        cache_key = f"{job_id}:{stage}:{int(elapsed // 5)}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        stage_index = STAGE_ORDER.index(stage) if stage in STAGE_ORDER else 0
        total_stages = len(STAGE_ORDER)

        model = self._get_aggregate_model(stage_index)
        if model and model.sample_count > 0:
            remaining = model.estimate_remaining(elapsed, stage_index, total_stages)
            if remaining is not None:
                result = {
                    "eta_seconds": round(remaining, 1),
                    "confidence": min(0.95, 0.3 + 0.1 * model.sample_count),
                    "method": "bayesian",
                    "sample_count": model.sample_count,
                }
                self._cache[cache_key] = result
                return result

        return None

    def _get_aggregate_model(self, stage_index: int) -> BayesianSimpleModel | None:
        agg = BayesianSimpleModel()
        found = False
        for job_models in self._models.values():
            if stage_index in job_models:
                for s in job_models[stage_index]._samples:
                    agg.add_sample(s)
                    found = True
        return agg if found else None

    async def get_historical_durations(self) -> dict[str, Any]:
        """Return aggregated historical duration statistics per stage."""
        stats: dict[str, dict[str, float]] = {}
        for stage_name in STAGE_ORDER:
            stage_index = STAGE_ORDER.index(stage_name)
            model = self._get_aggregate_model(stage_index)
            if model and model.sample_count > 0:
                samples = model._samples
                sorted_samples = sorted(samples)
                n = len(sorted_samples)
                stats[stage_name] = {
                    "mean": round(sum(samples) / n, 1),
                    "p50": round(sorted_samples[n // 2], 1),
                    "p90": round(sorted_samples[int(n * 0.9)], 1),
                    "p99": round(sorted_samples[min(int(n * 0.99), n - 1)], 1),
                    "count": n,
                }
        total_mean = sum(v["mean"] for v in stats.values()) if stats else 0
        return {
            "per_stage": stats,
            "total_mean_seconds": round(total_mean, 1),
        }


_eta_engine: ETAEngine | None = None


def get_eta_engine() -> ETAEngine:
    """Return the global ETA engine singleton."""
    global _eta_engine
    if _eta_engine is None:
        from src.dashboard.fastapi.config import FeatureFlags

        _eta_engine = ETAEngine(
            output_dir="output",
            history_path=FeatureFlags.ETA_HISTORICAL_DATA_PATH(),
            background_interval=FeatureFlags.ETA_ENGINE_BACKGROUND_INTERVAL_SECONDS(),
        )
    return _eta_engine
