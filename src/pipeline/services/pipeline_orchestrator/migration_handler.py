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

    async def verify_actor_alive(self, actor_id: str) -> bool: ...


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
        verification_timeout_seconds: float = 10.0,
        max_verification_retries: int = 3,
    ) -> None:
        self._coordinator = coordinator
        self._check_interval = check_interval_seconds
        self._cpu_threshold = cpu_threshold
        self._ram_threshold = ram_threshold
        self._active = False
        self._monitor_task: asyncio.Task | None = None
        self._actor_refs: dict[str, Any] = {}  # actor_id -> actor_ref
        self._verification_timeout = verification_timeout_seconds
        self._max_verification_retries = max_verification_retries

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
        from src.core.task_registry import get_task_registry

        self._monitor_task = get_task_registry().create_task(
            self._run_monitor(), owner="migration_handler", name="monitor"
        )
        logger.info(
            "ProactiveMigration: Handler started (Thresholds: CPU=%.1f%%, RAM=%.1f%%)",
            self._cpu_threshold,
            self._ram_threshold,
        )

    async def stop(self) -> None:
        """Stop the background monitoring loop."""
        self._active = False
        if self._monitor_task:
            self._monitor_task.cancel()
            try:
                await self._monitor_task
            except asyncio.CancelledError as exc:
                logger.warning("Operation failed in migration_handler.py: %s", exc, exc_info=True)  # noqa: BLE001
        logger.info("ProactiveMigration: Handler stopped")

    async def _verify_migration(self, actor_id: str) -> bool:
        """Verify that a migrated actor is alive on the destination before local removal.

        Retries up to ``_max_verification_retries`` times with a short delay
        between attempts to allow the remote actor time to start.
        """
        if not hasattr(self._coordinator, "verify_actor_alive"):
            logger.debug(
                "ProactiveMigration: Coordinator does not support verify_actor_alive; "
                "skipping verification for actor [%s]",
                actor_id,
            )
            return True

        for attempt in range(1, self._max_verification_retries + 1):
            try:
                alive = await asyncio.wait_for(
                    self._coordinator.verify_actor_alive(actor_id),
                    timeout=self._verification_timeout,
                )
                if alive:
                    logger.info(
                        "ProactiveMigration: Actor [%s] verified alive on destination (attempt %d/%d)",
                        actor_id,
                        attempt,
                        self._max_verification_retries,
                    )
                    return True
                logger.warning(
                    "ProactiveMigration: Actor [%s] NOT alive on destination (attempt %d/%d)",
                    actor_id,
                    attempt,
                    self._max_verification_retries,
                )
            except TimeoutError:
                logger.warning(
                    "ProactiveMigration: Verification timed out for actor [%s] (attempt %d/%d)",
                    actor_id,
                    attempt,
                    self._max_verification_retries,
                )
            except Exception as exc:
                logger.error(
                    "ProactiveMigration: Verification error for actor [%s] (attempt %d/%d): %s",
                    actor_id,
                    attempt,
                    self._max_verification_retries,
                    exc,
                )
                return False

            if attempt < self._max_verification_retries:
                await asyncio.sleep(1.0 * attempt)

        return False

    async def _run_monitor(self) -> None:
        """Main loop that scans active actors for health violations."""
        while self._active:
            try:
                actor_ids = list(self._actor_refs.keys())
                for actor_id in actor_ids:
                    actor_ref = self._actor_refs.get(actor_id)
                    if not actor_ref:
                        continue

                    migration_triggered = await self._coordinator.migrate_if_needed(
                        actor_ref, task_metadata={"actor_id": actor_id}
                    )

                    if migration_triggered:
                        verified = await self._verify_migration(actor_id)
                        if verified:
                            self.unregister_actor(actor_id)
                            get_event_bus().emit(
                                EventType.GHOST_ACTOR_EVACUATED,
                                source="proactive-migration-handler",
                                data={
                                    "actor_id": actor_id,
                                    "timestamp": time.time(),
                                    "reason": "resource_pressure_evacuation",
                                },
                            )
                        else:
                            logger.error(
                                "ProactiveMigration: Actor [%s] migration NOT verified; "
                                "keeping local reference to prevent actor loss",
                                actor_id,
                            )

            except Exception as e:
                logger.error("ProactiveMigration: Error in monitor loop: %s", e)

            await asyncio.sleep(self._check_interval)
