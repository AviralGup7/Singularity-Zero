"""Lifespan events for the FastAPI dashboard.

Startup is organized into phases for clarity. Each phase module handles
a single concern and runs in sequence. Shutdown runs phases in reverse.

Phase modules:
  - lifespan_core:         Logging, secrets, plugins, cache, services
  - lifespan_notifications: Notification storage, broadcaster, manager
  - lifespan_websocket:    WebSocket server with auth
  - lifespan_mesh:         Gossip, consensus, mDNS, sharding, bloom
  - lifespan_health:       Self-healing, corrective actions, telemetry
"""

import asyncio
import logging
import time
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI

from src.dashboard.fastapi.feature_flags import FeatureFlags
from src.dashboard.fastapi.spa import setup_mimetypes

try:
    import psutil
except ImportError:
    psutil = None

setup_mimetypes()

logger = logging.getLogger(__name__)

_START_TIME: float | None = None


# ---------------------------------------------------------------------------
# Background task registration (Bug #23)
# ---------------------------------------------------------------------------


def _register_background_tasks(app: FastAPI) -> None:
    """Register all background tasks with the lifecycle manager.

    Ensures tasks are cancelled during shutdown before cleanups run,
    preventing ghost listeners and duplicate subscriptions.
    """
    try:
        from src.core.lifecycle import get_lifecycle_manager

        mgr = get_lifecycle_manager()
    except ImportError:
        return

    # Cache analytics task
    if hasattr(app.state, "cache_analytics_task") and app.state.cache_analytics_task is not None:
        mgr.register_task("cache_analytics", app.state.cache_analytics_task)

    # ETA engine task
    if hasattr(app.state, "eta_task") and app.state.eta_task is not None:
        mgr.register_task("eta_engine", app.state.eta_task)

    # Consensus task (also registered in lifespan_mesh, but this is a safety net)
    if hasattr(app.state, "mesh_consensus_task") and app.state.mesh_consensus_task is not None:
        mgr.register_task("mesh_consensus", app.state.mesh_consensus_task)

    # Telemetry task
    if hasattr(app.state, "mesh_telemetry_task") and app.state.mesh_telemetry_task is not None:
        mgr.register_task("mesh_telemetry", app.state.mesh_telemetry_task)


# ---------------------------------------------------------------------------
# Shutdown helper
# ---------------------------------------------------------------------------


async def _shutdown(app: FastAPI, ws_services: Any) -> None:
    """Run all shutdown steps in reverse order."""
    logger.info("Dashboard lifecycle transition: SHUTDOWN")

    if hasattr(app.state, "mesh_telemetry_task"):
        app.state.mesh_telemetry_task.cancel()
        try:
            await app.state.mesh_telemetry_task
        except asyncio.CancelledError as exc:
            logger.warning("Operation failed in lifespan.py: %s", exc, exc_info=True)  # noqa: BLE001

    # Terminate running job processes BEFORE shutting down websocket
    if hasattr(app.state, "services") and hasattr(app.state.services, "jobs"):
        for job_id, job in app.state.services.jobs.items():
            if job.get("status") == "running":
                process = job.get("process")
                if process:
                    logger.info("Terminating process for job %s", job_id)
                    try:
                        process.terminate()
                        try:
                            process.wait(timeout=5.0)
                        except Exception:
                            # process.wait() not available or timed out — force kill
                            try:
                                process.kill()
                                process.wait(timeout=3.0)
                            except Exception:
                                logger.warning(
                                    "Failed to kill process for job %s", job_id
                                )
                    except Exception as exc:
                        logger.warning(
                            "Failed to terminate process for job %s: %s", job_id, exc
                        )

    await asyncio.sleep(0.5)

    if ws_services:
        await ws_services.shutdown()

    if getattr(app.state, "gossip", None) is not None:
        await app.state.gossip.stop()

    if hasattr(app.state, "mesh_consensus"):
        app.state.mesh_consensus.stop()
    if hasattr(app.state, "mesh_consensus_task"):
        app.state.mesh_consensus_task.cancel()
        try:
            await app.state.mesh_consensus_task
        except asyncio.CancelledError as exc:
            logger.warning("Operation failed in lifespan.py: %s", exc, exc_info=True)  # noqa: BLE001

    discovery = getattr(app.state, "worker_discovery", None)
    if discovery is not None:
        try:
            discovery.shutdown()
        except Exception:
            logger.exception("mDNS discovery shutdown raised")

    if hasattr(app.state, "cache_analytics_task"):
        app.state.cache_analytics_task.cancel()
        try:
            await app.state.cache_analytics_task
        except asyncio.CancelledError as exc:
            logger.warning("Operation failed in lifespan.py: %s", exc, exc_info=True)  # noqa: BLE001

    if hasattr(app.state, "cache_manager"):
        app.state.cache_manager.close()

    if hasattr(app.state, "self_healing_controller"):
        await app.state.self_healing_controller.stop()

    if hasattr(app.state, "bloom_mesh"):
        await app.state.bloom_mesh.stop()

    if FeatureFlags.ENABLE_BAYESIAN_ETA():
        if hasattr(app.state, "eta_task"):
            app.state.eta_task.cancel()
            try:
                await app.state.eta_task
            except asyncio.CancelledError:
                pass
        from src.dashboard.eta_engine import get_eta_engine

        await get_eta_engine().stop()

    if hasattr(app.state.services, "close_persistence"):
        app.state.services.close_persistence()

    if hasattr(app.state, "lifespan_lock"):
        app.state.lifespan_lock.release()

    from src.core.plugins.loader import stop_dynamic_plugin_watcher

    try:
        stop_dynamic_plugin_watcher()
    except Exception:
        logger.debug("Plugin watcher shutdown raised", exc_info=True)

    from src.core.utils.shared_sessions import async_close_all_clients

    await async_close_all_clients()

    # Reset singletons to prevent stale state on restart (Bug #24).
    # Singletons that survive process restart accumulate duplicate
    # listeners, callbacks, and background tasks.
    _reset_singletons()

    # Unregister the main event loop (Bug #22)
    from src.core.utils.async_bridge import reset_main_loop

    reset_main_loop()


def _reset_singletons() -> None:
    """Reset global singletons that hold background state.

    Prevents duplicate listeners, callbacks, and refreshers when the
    dashboard restarts within the same process (e.g. uvicorn --reload).
    """
    # Reset ETA engine singleton
    try:
        import src.dashboard.eta_engine as _eta_mod

        _eta_mod._eta_engine = None
    except (ImportError, AttributeError):
        pass

    # Reset learning integration singleton
    try:
        from src.learning.integration import _cleanup_learning_integration

        _cleanup_learning_integration()
    except (ImportError, Exception):
        pass

    # Reset unified cache singleton
    try:
        import src.pipeline.unified_cache as _cache_mod

        if hasattr(_cache_mod, "_unified_cache") and _cache_mod._unified_cache is not None:
            try:
                _cache_mod._unified_cache.close()
            except Exception:
                    logger.debug("Non-critical cleanup error", exc_info=True)
            _cache_mod._unified_cache = None
            # Reset the class-level instance too
            _cache_mod.UnifiedCache._instance = None
    except (ImportError, AttributeError):
        pass

    # Reset shared HTTP clients
    try:
        from src.core.utils import shared_sessions as _ss_mod

        with _ss_mod._async_clients_lock:
            _ss_mod._async_clients.clear()
        # Bug #20: Reset cleanup flag so next shutdown can close clients
        _ss_mod._cleanup_done = False
    except (ImportError, AttributeError):
        pass

    # Reset TaskRegistry singleton
    try:
        import src.core.task_registry as _tr_mod
        _tr_mod._registry = None
    except (ImportError, AttributeError):
        pass

    # Reset ConcurrencyGovernor singleton
    try:
        from src.core.concurrency_governor import reset_governor
        reset_governor()
    except (ImportError, Exception):
        pass

    # Bug #25: Reset CapacityManager singleton
    try:
        import src.core.capacity_manager as _cm_mod
        _cm_mod._capacity_manager = None
    except (ImportError, AttributeError):
        pass

    # Reset LifecycleManager singleton
    try:
        import src.core.lifecycle as _lc_mod
        _lc_mod._manager = None
        _lc_mod._atexit_registered = False
    except (ImportError, AttributeError):
        pass

    # Reset bridge executor
    try:
        import src.core.utils.async_bridge as _ab_mod
        if _ab_mod._bridge_executor is not None:
            _ab_mod._bridge_executor.shutdown(wait=False)
            _ab_mod._bridge_executor = None
    except (ImportError, AttributeError):
        pass

    logger.debug("Singleton reset complete")


# ---------------------------------------------------------------------------
# Main lifespan context manager
# ---------------------------------------------------------------------------


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None]:
    global _START_TIME
    _START_TIME = time.time()

    # Register the main event loop for cross-module coordination (Bug #22)
    from src.core.utils.async_bridge import register_main_loop

    register_main_loop(asyncio.get_running_loop())

    # Register plugin hooks from analysis and detection layers
    try:
        import src.analysis.plugin_registration  # noqa: F401
    except ImportError:
        pass
    try:
        import src.detection.cache_registration  # noqa: F401
    except ImportError:
        pass

    config: Any = app.state.config
    ws_services = None

    # Phase 1: Core infrastructure
    from src.dashboard.fastapi.lifespan_core import startup_core

    startup_core(app, config)

    # Phase 2: Notifications
    from src.dashboard.fastapi.lifespan_notifications import startup_notifications

    startup_notifications(app, config)

    # Phase 3: WebSocket
    from src.dashboard.fastapi.lifespan_websocket import startup_websocket

    ws_services = await startup_websocket(app, config)

    # Phase 4: Mesh infrastructure
    from src.dashboard.fastapi.lifespan_mesh import startup_mesh

    local_node, node_id = await startup_mesh(app, config)

    # Phase 5: Health monitoring & telemetry
    from src.dashboard.fastapi.lifespan_health import startup_health

    await startup_health(app, local_node, node_id, ws_services)

    # Optional: Bayesian ETA engine
    if FeatureFlags.ENABLE_BAYESIAN_ETA():
        from src.dashboard.fastapi.feature_flags_setup import maybe_start_bayesian_eta

        maybe_start_bayesian_eta(app)

    # Bug #23: Register all background tasks with lifecycle manager
    _register_background_tasks(app)

    logger.info("Neural-Mesh Infrastructure: ACTIVE (NodeID: %s)", node_id)
    logger.info("Dashboard lifecycle transition: READY")
    if psutil is None:
        logger.warning("psutil is not installed; mesh CPU/RAM telemetry will be unavailable")

    yield

    # Shutdown (reverse order)
    await _shutdown(app, ws_services)
