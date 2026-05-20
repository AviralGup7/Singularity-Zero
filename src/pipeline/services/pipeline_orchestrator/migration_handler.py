"""
Cyber Security Test Pipeline - Proactive Migration Handler
Monitors Neural-Mesh telemetry and triggers proactive actor migrations.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any, Protocol

from src.core.events import EventType, get_event_bus
from src.core.logging.trace_logging import get_pipeline_logger

logger = get_pipeline_logger(__name__)


class MeshTelemetryProvider(Protocol):
    """Protocol for providing real-time mesh health telemetry."""
    def get_mesh_health(self) -> dict[str, Any]: ...


class GhostActorCoordinator(Protocol):
    """Protocol for coordinating ghost-actor migrations."""
    async def migrate_if_needed(self, actor_ref: Any, task_metadata: dict[str, Any]) -> bool: ...


class ProactiveMigrationHandler:
    """
    Monitors node health across the mesh and initiates actor evacuations.
    Ensures zero-downtime execution by moving actors before hardware saturation.
    """

    def __init__(
        self,
        coordinator: Any,  # GhostMeshCoordinator
        check_interval_seconds: float = 30.0,
        cpu_threshold: float = 90.0,
        ram_threshold: float = 95.0,
    ) -> None:
        self._coordinator = coordinator
        self._check_interval = check_interval_seconds
        self._cpu_threshold = cpu_threshold
        self._ram_threshold = ram_threshold
        self._active = False
        self._monitor_task: asyncio.Task | None = None
        self._actor_refs: dict[str, Any] = {}  # actor_id -> actor_ref

    def register_actor(self, actor_id: str, actor_ref: Any) -> None:
        """Track an active actor for health monitoring."""
        self._actor_refs[actor_id] = actor_ref
        logger.debug("ProactiveMigration: Registered actor [%s]", actor_id)

    def unregister_actor(self, actor_id: str) -> None:
        """Stop tracking a completed or failed actor."""
        self._actor_refs.pop(actor_id, None)
        logger.debug("ProactiveMigration: Unregistered actor [%s]", actor_id)

    async def start(self) -> None:
        """Start the background monitoring loop."""
        if self._active:
            return
        self._active = True
        self._monitor_task = asyncio.create_task(self._run_monitor())
        logger.info("ProactiveMigration: Handler started (Thresholds: CPU=%.1f%%, RAM=%.1f%%)",
                    self._cpu_threshold, self._ram_threshold)

    async def stop(self) -> None:
        """Stop the background monitoring loop."""
        self._active = False
        if self._monitor_task:
            self._monitor_task.cancel()
            try:
                await self._monitor_task
            except asyncio.CancelledError:
                pass
        logger.info("ProactiveMigration: Handler stopped")

    async def _run_monitor(self) -> None:
        """Main loop that scans active actors for health violations."""
        while self._active:
            try:
                # 🛸 Sprint 1: Proactive Evaluation
                # Check health for each registered actor
                actor_ids = list(self._actor_refs.keys())
                for actor_id in actor_ids:
                    actor_ref = self._actor_refs.get(actor_id)
                    if not actor_ref:
                        continue

                    # Request a migration check from the coordinator
                    # The coordinator uses the balancer to decide if a better node exists.
                    migration_triggered = await self._coordinator.migrate_if_needed(
                        actor_ref,
                        task_metadata={"actor_id": actor_id}
                    )

                    if migration_triggered:
                        # Once migrated, we remove our local reference as the actor
                        # is now effectively on another node.
                        self.unregister_actor(actor_id)
                        
                        get_event_bus().emit(
                            EventType.GHOST_ACTOR_EVACUATED,
                            source="proactive-migration-handler",
                            data={
                                "actor_id": actor_id,
                                "timestamp": time.time(),
                                "reason": "resource_pressure_evacuation"
                            }
                        )

            except Exception as e:
                logger.error("ProactiveMigration: Error in monitor loop: %s", e)
            
            await asyncio.sleep(self._check_interval)
