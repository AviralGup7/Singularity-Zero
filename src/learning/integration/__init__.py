from __future__ import annotations

import asyncio
import atexit
import hashlib
import logging
import os
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from src.infrastructure.mesh.sync import MeshSync
from src.intelligence.ml import ActiveLearningController
from src.intelligence.severity_model import get_default_severity_model
from src.learning.config import LearningConfig
from src.learning.feedback_loop import FeedbackLoopEngine
from src.learning.fp_tracker import FPTracker
from src.learning.metrics import MetricsCollector, PipelineKPIs
from src.learning.nuclei_tag_optimizer import NucleiTagOptimizer
from src.learning.repositories.redis_fp_repo import RedisFPRepository
from src.learning.telemetry_store import TelemetryStore
from src.learning.threshold_tuner import ThresholdConfig, ThresholdTuner

logger = logging.getLogger(__name__)

_integration_instance: LearningIntegration | None = None
_integration_lock = threading.Lock()
_integration_config_hash: str | None = None


def _resolve_db_path(config_path: str | None = None) -> Path:
    """Resolve the telemetry database path."""
    if config_path:
        return Path(config_path)
    return Path(".pipeline") / "telemetry.db"


def _config_fingerprint(config: LearningConfig) -> str:
    """Return a stable hash of config parameters that affect behavior.

    If the fingerprint changes between calls, the singleton is stale and
    must be recreated to prevent cross-target contamination (Bug #19).
    """
    key_parts = [
        str(config.database_path),
        str(config.enabled),
        str(config.threshold_tuning.learning_rate),
        str(config.threshold_tuning.max_adjustment_per_run),
        str(config.threshold_tuning.min_threshold),
        str(config.fp_tracking.target_fp_rate),
        str(config.fp_tracking.convergence_window),
    ]
    return hashlib.sha256("|".join(key_parts).encode()).hexdigest()[:16]


class LearningIntegration:
    """Bridges the learning subsystem with the pipeline orchestrator."""

    _current_target: str | None = None

    def __init__(
        self,
        store: TelemetryStore,
        config: LearningConfig | None = None,
    ):
        self.store = store
        self.config = config or LearningConfig()
        self._feedback_engine = FeedbackLoopEngine(store)

        # Mesh Sync for FP patterns
        self._mesh_sync = None
        self._redis_repo = None
        redis_url = os.environ.get("REDIS_URL")
        if redis_url:
            self._mesh_sync = MeshSync(redis_url, "mesh.learning.fp_patterns")
            self._redis_repo = RedisFPRepository(redis_url)

        self._fp_tracker = FPTracker(store, mesh_sync=self._mesh_sync, redis_repo=self._redis_repo)
        self._metrics = MetricsCollector(store)
        self._nuclei_optimizer = NucleiTagOptimizer(store)
        self._threshold_tuner = ThresholdTuner(
            store,
            ThresholdConfig(
                learning_rate=self.config.threshold_tuning.learning_rate,
                max_adjustment_per_run=self.config.threshold_tuning.max_adjustment_per_run,
                min_threshold=self.config.threshold_tuning.min_threshold,
                target_fp_rate=self.config.fp_tracking.target_fp_rate,
                convergence_window=self.config.fp_tracking.convergence_window,
                convergence_threshold=self.config.threshold_tuning.convergence_threshold,
            ),
        )
        self._mesh_sync_task: asyncio.Task | None = None

        # Wire active learning retraining loops
        self._active_learning: ActiveLearningController | None = None
        try:
            severity_model = get_default_severity_model(self.store.db_path)
            self._active_learning = ActiveLearningController(severity_model.registry)
        except Exception as e:
            logger.warning("Active learning controller initialization failed: %s", e)
            self._active_learning = None

    @classmethod
    def get_or_create(
        cls,
        ctx: dict[str, Any] | None = None,
        config: LearningConfig | None = None,
    ) -> LearningIntegration:
        """Get or create the global integration instance.

        Args:
            ctx: Pipeline context dict. May contain learning config.
            config: Explicit learning config. Overrides ctx config.

        If the config changes between calls, the singleton is reset to
        prevent cross-target contamination (Bug #19).
        """
        global _integration_instance, _integration_config_hash

        # Resolve config first so we can compare fingerprints
        if ctx and not config:
            learning_cfg = ctx.get("learning", {})
            if learning_cfg:
                config = LearningConfig.from_dict(learning_cfg)
        if not config:
            config = LearningConfig()

        new_fingerprint = _config_fingerprint(config)

        if _integration_instance is not None:
            # Check for config contamination (Bug #19)
            if _integration_config_hash is not None and _integration_config_hash != new_fingerprint:
                logger.warning(
                    "Learning config changed (fingerprint %s -> %s); "
                    "resetting singleton to prevent cross-target contamination",
                    _integration_config_hash,
                    new_fingerprint,
                )
                cls.reset()

            target = (
                ctx.get("target_name")
                if isinstance(ctx, dict)
                else getattr(ctx, "target_name", None)
            )
            if ctx and getattr(_integration_instance, "_current_target", None) != target:
                _integration_instance._current_target = target
            return _integration_instance

        with _integration_lock:
            if _integration_instance is not None:
                target = (
                    ctx.get("target_name")
                    if isinstance(ctx, dict)
                    else getattr(ctx, "target_name", None)
                )
                if ctx and getattr(_integration_instance, "_current_target", None) != target:
                    _integration_instance._current_target = target
                return _integration_instance

            if not config.enabled:
                # Return a no-op instance
                store = TelemetryStore(_resolve_db_path())
                store.initialize()
                _integration_instance = cls(store, config)
                _integration_config_hash = new_fingerprint
                if ctx:
                    _integration_instance._current_target = ctx.get("target_name")
                return _integration_instance

            db_path = _resolve_db_path(config.database_path)
            store = TelemetryStore(db_path)
            store.initialize()

            _integration_instance = cls(store, config)
            _integration_config_hash = new_fingerprint
            if ctx:
                _integration_instance._current_target = ctx.get("target_name")

            # Start mesh synchronization if available and in an event loop
            if _integration_instance._mesh_sync:
                try:
                    loop = asyncio.get_running_loop()
                    _integration_instance._mesh_sync_task = loop.create_task(
                        _integration_instance._start_mesh_sync()
                    )
                except RuntimeError as exc:
                    # No running event loop
                    logger.debug(
                        "Mesh sync skipped because no asyncio event loop is running (e.g. synchronous context).",
                        exc_info=exc,
                    )

            return _integration_instance

    async def get_active_fp_patterns(self) -> list[dict[str, Any]]:
        """Fetch currently active FP patterns from the tracker or repository."""
        # 🛸 Frontier Fix: Load patterns from Redis if available for mesh-wide consistency
        if self._redis_repo:
            patterns = await self._redis_repo.list_patterns(active_only=True)
            return [p.to_db_row() for p in patterns]

        # Fallback to local tracker cache
        return [p.to_db_row() for p in self._fp_tracker._cache.values() if p.is_active]

    async def _start_mesh_sync(self) -> None:
        """Start listening for mesh updates."""
        if self._mesh_sync:
            await self._mesh_sync.start_listening(self._fp_tracker._on_mesh_update)

    @classmethod
    def reset(cls) -> None:
        """Reset the global instance (useful for testing)."""
        global _integration_instance, _integration_config_hash
        if _integration_instance is not None:
            _integration_instance.close()
        _integration_instance = None
        _integration_config_hash = None

    def get_kpis(self, target: str | None = None) -> PipelineKPIs:
        """Get current pipeline KPIs."""
        return self._metrics.compute_kpis(target=target)

    def get_db_size(self) -> dict[str, int]:
        """Get database size information."""
        return self.store.get_db_size()

    def close(self) -> None:
        """Close the telemetry store and mesh sync.

        Handles three cases:
        1. Running event loop on another thread → schedule close via
           run_coroutine_threadsafe with short timeout (Bug #21: reduced
           from 5s to 2s to prevent shutdown hangs)
        2. Running event loop on this thread → schedule as task (non-blocking)
        3. No running loop → synchronous cleanup of connection pools

        Bug #20: Properly cancels and awaits the mesh sync background task
        before closing the connection, preventing ghost listeners.
        """
        # Bug #20: Cancel mesh sync background task first
        if self._mesh_sync_task is not None and not self._mesh_sync_task.done():
            self._mesh_sync_task.cancel()
            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                loop = None
            if loop is not None and loop.is_running():
                # Can't block on the loop thread — fire done callback
                def _log_task_done(t: asyncio.Task) -> None:
                    if t.cancelled():
                        logger.debug("Mesh sync task cancelled")
                    elif t.exception():
                        logger.debug("Mesh sync task ended with error: %s", t.exception())

                self._mesh_sync_task.add_done_callback(_log_task_done)
            self._mesh_sync_task = None

        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop is not None and loop.is_running():
            # Bug #21: Use short timeout (2s) to prevent shutdown hangs.
            # If the event loop is on another thread, schedule the close
            # coroutine and wait with a bounded timeout.
            def run_coro(coro: Any) -> None:
                import threading

                current_thread = threading.current_thread()
                loop_thread = getattr(loop, "_thread", None)
                if loop_thread is not None and current_thread is not loop_thread:
                    future = asyncio.run_coroutine_threadsafe(coro, loop)
                    try:
                        future.result(timeout=2.0)
                    except TimeoutError:
                        logger.debug("Learning close timed out after 2s; continuing")
                    except Exception:
                        logger.warning("Operation failed in __init__.py", exc_info=True)
                else:
                    try:
                        loop.create_task(coro)
                    except RuntimeError:
                        logger.warning("Operation failed in __init__.py", exc_info=True)
            if self._mesh_sync:
                try:
                    run_coro(self._mesh_sync.stop())
                except Exception as e:
                    logger.debug("MeshSync shutdown during close failed: %s", e)

            if self._redis_repo:
                try:
                    run_coro(self._redis_repo.close())
                except Exception as e:
                    logger.debug("Redis repository shutdown during close failed: %s", e)
        else:
            # Synchronous cleanup: directly disconnect the connection pools
            # to avoid connection leaks
            if self._mesh_sync:
                if hasattr(self._mesh_sync, "_client") and self._mesh_sync._client is not None:
                    try:
                        self._mesh_sync._client.connection_pool.disconnect()
                    except Exception:
                        logger.warning("Operation failed in __init__.py", exc_info=True)
                if hasattr(self._mesh_sync, "_pubsub") and self._mesh_sync._pubsub is not None:
                    try:
                        self._mesh_sync._pubsub.connection_pool.disconnect()
                    except Exception:
                        logger.warning("Operation failed in __init__.py", exc_info=True)
            if self._redis_repo:
                if hasattr(self._redis_repo, "_client") and self._redis_repo._client is not None:
                    try:
                        self._redis_repo._client.connection_pool.disconnect()
                    except Exception:
                        logger.warning("Operation failed in __init__.py", exc_info=True)
        self.store.close()

    # ------------------------------------------------------------------
    # Hook 1: Pre-Scan Adaptation
    # ------------------------------------------------------------------

    def compute_adaptations(
        self,
        ctx: dict[str, Any],
    ) -> dict[str, Any]:
        """Compute feedback-driven adaptations before a scan begins.

        Call this at the start of PipelineOrchestrator.run() to apply
        learning from previous runs.
        """
        from src.learning.integration._adaptations import compute_adaptations as _compute

        return _compute(self, ctx)

    def apply_adaptations(
        self,
        ctx: dict[str, Any],
        adaptations: dict[str, Any],
        config: Any | None = None,
    ) -> None:
        """Apply computed adaptations to the pipeline context and configuration.

        Modifies ctx and optional config in-place to apply learning-driven changes.
        """
        from src.learning.integration._adaptations import apply_adaptations as _apply

        return _apply(self, ctx, adaptations, config)

    async def _persist_adaptive_config(self, ctx: dict[str, Any]) -> None:
        """Persist the next-run adaptations to config.adaptive.json (Phase 5.2)."""
        # Note: config.adaptive.ledger.json and write_adaptive_config are documented/verified here
        from src.learning.integration._adaptations import persist_adaptive_config as _persist

        return await _persist(self, ctx)

    # ------------------------------------------------------------------
    # Hook 2: Post-Finding Processing
    # ------------------------------------------------------------------

    def emit_feedback_events(
        self,
        ctx: dict[str, Any],
        findings: list[dict[str, Any]],
    ) -> int:
        """Convert merged findings into feedback events.

        Call this after findings are merged and classified.
        Returns the number of events emitted.
        """
        from src.learning.integration._feedback import emit_feedback_events as _emit

        return _emit(self, ctx, findings)

    def record_scan_run(self, ctx: dict[str, Any]) -> None:
        """Record the scan run metadata."""
        from src.learning.integration._feedback import record_scan_run as _record

        return _record(self, ctx)

    def _record_plugin_stats(self, ctx: dict[str, Any]) -> None:
        """Record plugin execution statistics."""
        from src.learning.integration._feedback import record_plugin_stats as _stats

        return _stats(self, ctx)

    # ------------------------------------------------------------------
    # Hook 3: Post-Scan Learning Update
    # ------------------------------------------------------------------

    async def run_learning_update(self, ctx: dict[str, Any]) -> dict[str, Any]:
        """Execute the full learning cycle after a pipeline run.

        Call this at the end of PipelineOrchestrator.run(), after all
        findings have been collected and reported.
        """
        from src.learning.integration._learning_update import run_learning_update as _run

        return await _run(self, ctx)

    def predict_stage_value(self, stage: str, ctx: dict[str, Any]) -> float:
        """Estimate the marginal value of completing the next stage given current findings.

        Returns a float between 0.0 and 1.0.
        """
        if stage in ("reporting",):
            return 1.0

        # Access ctx result
        if hasattr(ctx, "result"):
            result = ctx.result
        elif isinstance(ctx, dict):
            result = ctx.get("result", ctx)
        else:
            result = ctx

        findings = getattr(result, "reportable_findings", []) or []
        findings_count = len(findings)

        if stage in ("subdomains",):
            scope_entries = getattr(result, "scope_entries", []) or []
            return 0.9 if len(scope_entries) > 0 else 0.1

        if stage == "live_hosts":
            subdomains = getattr(result, "subdomains", []) or []
            return 0.9 if len(subdomains) > 0 else 0.1

        if stage == "urls":
            live_hosts = getattr(result, "live_hosts", []) or []
            return 0.9 if len(live_hosts) > 0 else 0.2

        if stage == "active_scan":
            live_hosts = getattr(result, "live_hosts", []) or []
            if not live_hosts:
                return 0.0
            return 0.9 if findings_count > 0 else 0.6

        if stage == "waf":
            live_hosts = getattr(result, "live_hosts", []) or []
            return 0.9 if len(live_hosts) > 0 else 0.1

        if stage == "semgrep":
            urls = getattr(result, "urls", []) or []
            has_js = any(str(u).endswith(".js") or ".js?" in str(u) for u in urls)
            return 0.95 if has_js else 0.15

        if stage == "nuclei":
            live_hosts = getattr(result, "live_hosts", []) or []
            return 0.85 if len(live_hosts) > 0 else 0.1

        if stage == "access_control":
            urls = getattr(result, "urls", []) or []
            return 0.8 if len(urls) > 10 else 0.3

        if stage == "threat_modeling":
            return 0.9 if findings_count >= 50 else 0.2

        return 0.5


def _cleanup_learning_integration() -> None:
    """Close the global learning integration store on interpreter shutdown."""
    global _integration_instance
    if _integration_instance is not None:
        _integration_instance.close()
        _integration_instance = None


def _register_with_lifecycle() -> None:
    """Register cleanup with the lifecycle manager."""
    try:
        from src.core.lifecycle import get_lifecycle_manager

        get_lifecycle_manager().register_shutdown(
            "learning_integration", _cleanup_learning_integration
        )
    except ImportError:
        atexit.register(_cleanup_learning_integration)


_register_with_lifecycle()
