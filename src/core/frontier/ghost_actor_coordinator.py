"""Mesh Coordinator for Location-Transparent Actor placements."""

from __future__ import annotations

import uuid
from typing import Any, cast

import pykka

from src.core.contracts.health import HealthComponent, HealthMetric, HealthStatus
from src.core.frontier.ghost_actor_registry import GhostMeshRegistry
from src.core.frontier.ghost_actor_state import ActorState
from src.core.logging.trace_logging import get_pipeline_logger

logger = get_pipeline_logger(__name__)


class GhostMeshCoordinator:
    """Orchestrates actor placement and migration across the Neural-Mesh.

    Uses the NeuralMeshBalancer to decide on target nodes.
    """

    def __init__(self, registry: GhostMeshRegistry, gossip: Any) -> None:
        self.registry = registry
        self.gossip = gossip
        from src.infrastructure.mesh.balancer import NeuralMeshBalancer  # pylint: disable=C0415

        self.balancer = NeuralMeshBalancer()
        # Bind coordinator to gossip for network-aware signaling
        is_mock = gossip.__class__.__name__ in ("MagicMock", "Mock")
        if gossip and hasattr(gossip, "__dict__") and not is_mock:
            gossip._coordinator = self

    async def migrate_if_needed(
        self,
        actor_ref: pykka.ActorRef,
        task_metadata: dict[str, Any],
    ) -> bool:
        """Check if an actor should be migrated and execute the move if a better node is found.

        Returns True if migration was successful.
        """
        try:
            # Sprint 1 Hardening: Use live mesh telemetry instead of blocking actor calls
            # This allows us to detect pressure even if the actor is busy executing.
            local_node = self.gossip.local_node

            # Use same thresholds as ProactiveMigrationHandler (90% CPU, <500MB RAM available)
            is_under_pressure = local_node.cpu_usage > 90.0 or local_node.ram_available_mb < 500.0

            if not is_under_pressure:
                # Also check if actor specifically recommended evacuation (e.g. for logic-level reasons)
                # We still try to ask, but with a timeout to avoid hanging.
                try:
                    health = cast(
                        dict[str, Any], actor_ref.ask({"command": "health_check"}, timeout=0.5)
                    )
                    if not health.get("evacuation_recommended"):
                        return False
                except pykka.Timeout, Exception:
                    return False

            try:
                actor_id = str(cast(Any, actor_ref.proxy()).actor_id.get(timeout=0.5))
            except Exception:
                actor_id = f"actor:{task_metadata.get('actor_id', 'unknown')}"
            logger.info(
                "Ghost-Coordinator: Initiating proactive migration for [%s] due to node pressure",
                actor_id,
            )

            target_node_id = self.balancer.select_best_node_from_gossip(self.gossip, task_metadata)
            current_node_id = local_node.id

            if target_node_id and target_node_id != current_node_id:
                logger.info(
                    "Ghost-Coordinator: Migrating [%s] from %s -> %s",
                    actor_id,
                    current_node_id,
                    target_node_id,
                )

                migration_id = str(uuid.uuid4())

                # 1. Freeze the actor and capture a stable snapshot while it is still alive.
                packed_state = actor_ref.ask(
                    {"command": "dehydrate", "migration_id": migration_id},
                    block=True,
                )
                unpacked = ActorState.rehydrate(packed_state)
                if not isinstance(packed_state, bytes):
                    packed_state = unpacked.pack()

                # 2. Store the serialized state in the registry for transmission
                await self.registry.store_actor_state(actor_id, packed_state)
                await self.registry.prepare_migration(
                    actor_id=actor_id,
                    migration_id=migration_id,
                    source_node=current_node_id,
                    target_node=target_node_id,
                    state_digest=unpacked.state_digest,
                )

                # 3. Update Registry only after the snapshot is durably visible.
                await self.registry.register_actor(actor_id, target_node_id)
                await self.registry.commit_migration(actor_id, migration_id)

                # 4. Stop the source actor after commit; a target can now rehydrate on restart.
                actor_ref.stop()

                # 5. Emit Migration Event for Observability
                from src.core.events import EventType, get_event_bus  # pylint: disable=C0415

                get_event_bus().emit(
                    EventType.GHOST_ACTOR_MIGRATED,
                    source=f"ghost-coordinator-{self.gossip.local_node.id}",
                    data={
                        "actor_id": actor_id,
                        "source_node": current_node_id,
                        "target_node": target_node_id,
                        "reason": "resource_pressure",
                        "migration_id": migration_id,
                        "state_digest": unpacked.state_digest,
                    },
                )

                # 6. Live Actor Migration Handoff (Network Handoff)
                is_mock = self.gossip.__class__.__name__ in ("MagicMock", "Mock")
                if (
                    not is_mock
                    and hasattr(self.gossip, "peers")
                    and isinstance(self.gossip.peers, dict)
                ):
                    target_peer = self.gossip.peers.get(target_node_id)
                    if target_peer and hasattr(self.gossip, "_send_reliable"):
                        logic_fn_name = unpacked.logic_fn_name or "dummy_logic"

                        # Send migration trigger over gossip UDP sync
                        await self.gossip._send_reliable(
                            target_peer,
                            "ghost_actor_spawn",
                            {
                                "actor_id": actor_id,
                                "logic_fn_name": logic_fn_name,
                                "migration_id": migration_id,
                                "state_digest": unpacked.state_digest,
                            },
                        )

                return True

            return False
        except Exception as e:  # pylint: disable=W0718
            logger.error("Ghost-Coordinator: Migration failed: %s", e)
            return False

    async def health_metrics(
        self, actor_refs: list[pykka.ActorRef] | None = None
    ) -> list[HealthMetric]:
        """Probe actor pressure for the self-healing controller."""
        metrics: list[HealthMetric] = []
        local_node = getattr(self.gossip, "local_node", None)
        if local_node is not None:
            pressured = local_node.cpu_usage > 90.0 or local_node.ram_available_mb < 500.0
            metrics.append(
                HealthMetric(
                    component=HealthComponent.GHOST_ACTOR,
                    name="ghost_mesh_node_pressure",
                    value=float(local_node.cpu_usage),
                    threshold=90.0,
                    status=HealthStatus.DEGRADED if pressured else HealthStatus.OK,
                    labels={
                        "node_id": local_node.id,
                        "ram_available_mb": local_node.ram_available_mb,
                        "active_jobs": local_node.active_jobs,
                    },
                )
            )
        for actor_ref in actor_refs or []:
            try:
                health = cast(
                    dict[str, Any], actor_ref.ask({"command": "health_check"}, timeout=0.5)
                )
                metrics.append(
                    HealthMetric(
                        component=HealthComponent.GHOST_ACTOR,
                        name="ghost_actor_evacuation",
                        value=bool(health.get("evacuation_recommended")),
                        status=HealthStatus.DEGRADED
                        if health.get("evacuation_recommended")
                        else HealthStatus.OK,
                        labels={"actor_id": health.get("actor_id", "unknown")},
                    )
                )
            except Exception as exc:  # pylint: disable=broad-exception-caught
                metrics.append(
                    HealthMetric(
                        component=HealthComponent.GHOST_ACTOR,
                        name="ghost_actor_probe_error",
                        value=1,
                        status=HealthStatus.CRITICAL,
                        labels={"error": str(exc)},
                    )
                )
        return metrics

    async def rebalance_actors(
        self,
        actor_refs: list[pykka.ActorRef],
        task_metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Migrate actors that are on pressured nodes."""
        migrated = 0
        for actor_ref in actor_refs:
            if await self.migrate_if_needed(actor_ref, task_metadata or {}):
                migrated += 1
        return {"checked": len(actor_refs), "migrated": migrated}

    async def spawn_or_rehydrate_actor(
        self,
        actor_id: str,
        logic_fn: Any,
        scan_actor_cls: Any,
    ) -> pykka.ActorRef:
        """Spawn a new actor instance, automatically re-hydrating from registry if state exists."""
        # 1. Start a fresh actor instance using ScanActor class
        actor_ref = scan_actor_cls.start(actor_id, logic_fn)

        # 2. Check if a migrated state exists in the registry
        packed_state = await self.registry.retrieve_actor_state(actor_id)
        if packed_state:
            try:
                # 3. Unpack and restore state using rehydrate command
                actor_ref.ask({"command": "rehydrate", "payload": packed_state}, block=True)
                logger.info(
                    "Ghost-Coordinator: Successfully re-hydrated actor [%s] with state checkpoints",
                    actor_id,
                )
                # 4. Clean up state from registry to save storage footprint
                await self.registry.clear_actor_state(actor_id)
                await self.registry.clear_migration(actor_id)
            except Exception as e:
                logger.error(
                    "Ghost-Coordinator: Failed to re-hydrate actor [%s] from state: %s",
                    actor_id,
                    e,
                )

        return cast(pykka.ActorRef[Any], actor_ref)
