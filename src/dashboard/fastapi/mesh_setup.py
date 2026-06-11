"""Mesh and bloom filter setup helpers for the FastAPI dashboard."""

import os
import secrets
import time
import uuid
from typing import TYPE_CHECKING, Any

from src.core.frontier.bloom import NeuralBloomFilter
from src.core.frontier.bloom_mesh import NeuralBloomMesh
from src.dashboard.fastapi.config import DashboardConfig
from src.infrastructure.mesh.gossip import GossipEngine, MeshNode
from src.infrastructure.mesh.manifest import discover_manifest
from src.infrastructure.mesh.sharding import MeshShardManager

if TYPE_CHECKING:
    pass

try:
    import psutil
except ImportError:
    psutil = None

logger = __import__("logging").getLogger(__name__)


def create_local_node(config: DashboardConfig) -> MeshNode:
    node_id = f"worker-{uuid.uuid4().hex[:8]}"
    if psutil:
        psutil.cpu_percent(interval=None)

    manifest = discover_manifest()
    return MeshNode(
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


def resolve_mesh_secret() -> str:
    mesh_secret = os.getenv("MESH_SECRET")
    is_prod = os.getenv("APP_ENV") == "production"

    if not mesh_secret:
        if is_prod:
            raise ValueError(
                "CRITICAL SECURITY RISK: MESH_SECRET environment variable is required in production."
            )
        mesh_secret = secrets.token_hex(32)
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

    return mesh_secret


def create_gossip_engine(node: MeshNode, secret: str) -> GossipEngine:
    return GossipEngine(node, secret=secret)


def create_shard_manager(
    node_id: str,
    *,
    weight: float = 1.0,
    region: str = "",
) -> MeshShardManager:
    shard_manager = MeshShardManager()
    shard_manager.add_node(node_id, weight=weight, region=region)
    return shard_manager


def init_bloom_filter() -> NeuralBloomFilter:
    capacity = int(os.getenv("BLOOM_CAPACITY", "1000000"))
    error_rate = float(os.getenv("BLOOM_ERROR_RATE", "0.001"))
    return NeuralBloomFilter(capacity=capacity, error_rate=error_rate)


def init_bloom_mesh(
    bloom_filter: NeuralBloomFilter, node_id: str, redis_url: str | None
) -> NeuralBloomMesh:
    return NeuralBloomMesh(bloom_filter, node_id=node_id, redis_url=redis_url)


def create_worker_discovery(
    node: MeshNode,
    *,
    secret: str,
    enable: bool = True,
) -> Any | None:
    """Wire up HMAC-signed mDNS discovery for the local node.

    Returns ``None`` if discovery is disabled (default behaviour is
    driven by the ``DASHBOARD_ENABLE_MDNS_DISCOVERY`` env var, falling
    back to the ``MESH_ENABLE_MDNS`` legacy key).  Discovery failures
    are non-fatal: the returned object simply reports
    ``is_enabled=False`` and the rest of the mesh keeps running.

    The ``zeroconf`` import is intentionally lazy so environments
    without mDNS (CI, minimal containers) can still import this
    module.
    """

    if not enable:
        return None
    if os.getenv("DASHBOARD_ENABLE_MDNS_DISCOVERY", "").lower() in {"0", "false", "no"}:
        return None
    if os.getenv("MESH_ENABLE_MDNS", "1").lower() in {"0", "false", "no"}:
        return None

    try:
        from src.infrastructure.discovery.mdns import WorkerDiscovery
    except ImportError as exc:  # noqa: BLE001
        logger.warning("mDNS discovery unavailable: %s", exc)
        return None

    advertised = {
        "capabilities": list(node.capabilities),
        "region": node.region,
        "zone": node.zone,
        "bandwidth_mbps": node.bandwidth_mbps,
        "capacity_weight": node.capacity_weight,
        "version_vector": dict(node.version_vector),
    }
    try:
        discovery = WorkerDiscovery(
            node.id,
            port=node.port,
            metadata=advertised,
            secret=secret,
            on_change=None,
        )
    except Exception as exc:  # noqa: BLE001 - keep bootstrap resilient
        logger.warning("mDNS discovery unavailable: %s", exc)
        return None
    return discovery
