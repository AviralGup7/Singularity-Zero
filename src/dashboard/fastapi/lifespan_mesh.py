"""Phase 4: Mesh infrastructure startup — gossip, consensus, mDNS, sharding, bloom."""

from __future__ import annotations

import asyncio
import logging
import os
import secrets as _secrets
import time
import uuid
from typing import Any

from fastapi import FastAPI

from src.dashboard.fastapi.feature_flags import FeatureFlags
from src.dashboard.fastapi.mesh_setup import (
    create_worker_discovery,
    init_bloom_filter,
    init_bloom_mesh,
)
from src.infrastructure.frontier.bloom_mesh import ReconcileBloom
from src.infrastructure.mesh.consensus import MeshConsensus
from src.infrastructure.mesh.gossip import GossipEngine, MeshNode
from src.infrastructure.mesh.manifest import discover_manifest
from src.infrastructure.mesh.sharding import MeshShardManager

try:
    import psutil
except ImportError:
    psutil = None

logger = logging.getLogger(__name__)


def _init_model_registry() -> Any:
    return None


async def startup_mesh(
    app: FastAPI, config: Any
) -> tuple[MeshNode | None, str | None]:
    """Mesh infrastructure — gossip, consensus, mDNS, sharding, bloom."""
    node_id = f"worker-{uuid.uuid4().hex[:8]}"
    if psutil:
        psutil.cpu_percent(interval=None)

    manifest = discover_manifest()
    local_node = MeshNode(
        id=node_id,
        host=os.getenv("MESH_BIND_INTERFACE", config.host),
        port=config.port,
        status="alive",
        cpu_usage=psutil.cpu_percent(interval=0.1) if psutil else 0.0,
        ram_available_mb=psutil.virtual_memory().available / 1024 / 1024 if psutil else 0.0,
        active_jobs=0,
        last_seen=time.time(),
        capabilities=list(manifest.capabilities),
        region=manifest.region,
        zone=manifest.zone,
        bandwidth_mbps=manifest.bandwidth_mbps,
        capacity_weight=manifest.capacity_weight,
        version_vector={node_id: 1},
    )

    mesh_secret = os.getenv("MESH_SECRET")
    is_prod = os.getenv("APP_ENV") == "production"

    if not mesh_secret:
        if is_prod:
            raise ValueError(
                "CRITICAL SECURITY RISK: MESH_SECRET environment variable is required in production."
            )
        mesh_secret = _secrets.token_hex(32)
        logger.warning(
            "MESH_SECRET is not set; generated a per-process random secret. "
            "Mesh peers will NOT be able to authenticate each other. "
            "Set MESH_SECRET to a long, random, shared value in any environment "
            "with more than one dashboard instance."
        )
    elif is_prod and mesh_secret in (
        "frontier-default-secret",
        "frontier-default-secret-change-in-prod",
        "frontier-default-secret-change-me",
    ):
        raise ValueError(
            "CRITICAL SECURITY RISK: MESH_SECRET must not be a default value in production."
        )

    gossip_engine = GossipEngine(local_node, secret=mesh_secret)
    if FeatureFlags.ENABLE_MESH():
        try:
            await asyncio.wait_for(gossip_engine.start(), timeout=10.0)
        except TimeoutError:
            logger.warning("Gossip mesh disabled because startup timed out after 10s")
            app.state.gossip = None
        except OSError as exc:
            logger.warning("Gossip mesh disabled because UDP bind failed: %s", exc)
            app.state.gossip = None
        else:
            app.state.gossip = gossip_engine
    else:
        logger.info("Mesh gossip disabled by feature flag ENABLE_MESH=false")
        app.state.gossip = None

    if FeatureFlags.ENABLE_CONSENSUS():
        # Finding 8: Skip MeshConsensus if gossip_engine is None (startup
        # timed out or failed).  MeshConsensus requires a working gossip
        # transport; creating it with None will crash during maintenance.
        if app.state.gossip is None:
            logger.info(
                "Mesh consensus skipped: gossip engine is not running"
            )
            app.state.mesh_consensus = None
        else:
            consensus = MeshConsensus(gossip_engine, redis_url=config.redis_url)
            app.state.mesh_consensus = consensus
            # Bug #3: Use TaskRegistry for all task creation to consolidate ownership.
            try:
                from src.core.task_registry import get_task_registry
                consensus_task = get_task_registry().create_task(
                    consensus.run_maintenance(),
                    owner="mesh_consensus",
                    name="consensus_maintenance",
                )
            except ImportError:
                consensus_task = asyncio.create_task(
                    consensus.run_maintenance(), name="mesh-consensus"
                )
                try:
                    from src.core.lifecycle import get_lifecycle_manager
                    get_lifecycle_manager().register_task("mesh_consensus", consensus_task)
                except ImportError:
                    logger.warning("Operation failed in lifespan_mesh.py", exc_info=True)
            app.state.mesh_consensus_task = consensus_task
    else:
        logger.info("Mesh consensus disabled by feature flag ENABLE_CONSENSUS=false")

    app.state.worker_discovery = None
    try:
        discovery = create_worker_discovery(local_node, secret=mesh_secret, enable=True)
        if discovery is not None:

            def _on_discovery_change(action: str, payload: Any) -> None:
                if action != "add":
                    return
                if not isinstance(payload, dict):
                    return
                # Finding 4: Use app.state.gossip instead of the captured
                # gossip_engine variable.  If gossip startup failed,
                # app.state.gossip is None and we must skip registration.
                _active_gossip = getattr(app.state, "gossip", None)
                if _active_gossip is None:
                    return
                try:
                    _active_gossip.register_discovered_peer(payload)
                except Exception:
                    logger.exception("Failed to register mDNS-discovered peer")

            discovery._on_change = _on_discovery_change
            if discovery.register() and discovery.start_discovery():
                app.state.worker_discovery = discovery
    except Exception as exc:  # noqa: BLE001
        logger.warning("mDNS discovery bootstrap failed; continuing without it: %s", exc)

    shard_manager = MeshShardManager()
    shard_manager.add_node(
        node_id,
        weight=manifest.capacity_weight,
        region=manifest.region,
    )
    app.state.sharding = shard_manager

    if FeatureFlags.ENABLE_BLOOM_MESH():
        bloom_filter = init_bloom_filter()
        bloom_mesh = init_bloom_mesh(bloom_filter, node_id=node_id, redis_url=config.redis_url)
        try:
            await asyncio.wait_for(bloom_mesh.start(), timeout=10.0)
        except TimeoutError:
            logger.warning("Bloom mesh startup timed out after 10s; continuing without it")
        except Exception as exc:  # noqa: BLE001
            logger.warning("Bloom mesh startup failed: %s", exc)
        app.state.bloom_filter = bloom_filter
        app.state.bloom_mesh = bloom_mesh
        app.state.bloom_reconciler = ReconcileBloom(bloom_mesh)
    else:
        logger.info("Bloom mesh disabled by feature flag ENABLE_BLOOM_MESH=false")
        app.state.bloom_filter = None
        app.state.bloom_mesh = None
        app.state.bloom_reconciler = None
    app.state.model_registry = _init_model_registry()

    return local_node, node_id
