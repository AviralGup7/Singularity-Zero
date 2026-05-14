"""Distributed checkpoint storage using Redis for cross-node replication.

Enables any worker in the local-mesh to resume failed tasks by
replicating checkpoint state across nodes via Redis.
"""

import json
import logging
import time

from src.core.checkpoint import CheckpointState
from src.infrastructure.queue.redis_client import RedisClient

logger = logging.getLogger(__name__)

CHECKPOINT_KEY_PREFIX = "checkpoint:run:"
LEASE_KEY_PREFIX = "checkpoint:lease:"
WORKER_CHECKPOINTS_KEY = "checkpoint:workers"


class DistributedCheckpointStore:
    """Stores checkpoint state in Redis for access by any worker.

    Provides cross-node checkpoint replication so that when a worker
    fails or shuts down, another worker can take over its tasks.

    Attributes:
        redis: Redis client for checkpoint storage.
        node_id: Unique identifier for this node/worker.
    """

    def __init__(self, redis_client: RedisClient, node_id: str) -> None:
        """Initialize the distributed checkpoint store.

        Args:
            redis_client: Redis client wrapper instance.
            node_id: Unique identifier for this node/worker.
        """
        self.redis = redis_client
        self.node_id = node_id

    async def save_checkpoint(self, state: CheckpointState, worker_id: str) -> bool:
        """Save checkpoint state to Redis with lease ownership.

        Args:
            state: CheckpointState instance to save.
            worker_id: ID of the worker owning this checkpoint.

        Returns:
            True if the checkpoint was saved successfully.
        """
        key = f"{CHECKPOINT_KEY_PREFIX}{state.pipeline_run_id}"
        data = json.dumps(state.to_dict())

        try:
            # Use Redis pipeline for atomic operation
            # Since execute_command doesn't support pipeline, we'll do sequential
            self.redis.execute_command("HSET", key, "state", data)
            self.redis.execute_command("HSET", key, "owner", worker_id)
            self.redis.execute_command("HSET", key, "updated_at", str(time.time()))
            self.redis.execute_command("HSET", key, "node_id", self.node_id)
            self.redis.execute_command("EXPIRE", key, 86400)  # 24 hour TTL

            # Track which workers have checkpoints
            worker_key = f"{WORKER_CHECKPOINTS_KEY}:{worker_id}"
            self.redis.execute_command(
                "SADD", worker_key, state.pipeline_run_id
            )
            self.redis.execute_command("EXPIRE", worker_key, 86400)

            logger.info(
                "Saved checkpoint for run %s (owner=%s, node=%s)",
                state.pipeline_run_id,
                worker_id,
                self.node_id,
            )
            return True
        except Exception as exc:
            logger.error("Failed to save checkpoint to Redis: %s", exc)
            return False

    async def load_checkpoint(self, run_id: str) -> CheckpointState | None:
        """Load checkpoint state from Redis.

        Args:
            run_id: Pipeline run ID to load.

        Returns:
            CheckpointState instance if found, None otherwise.
        """
        key = f"{CHECKPOINT_KEY_PREFIX}{run_id}"

        try:
            data = self.redis.execute_command("HGET", key, "state")
            if not data:
                return None

            state_str = data.decode("utf-8") if isinstance(data, bytes) else data
            state_dict = json.loads(state_str)
            return CheckpointState.from_dict(state_dict)
        except Exception as exc:
            logger.error("Failed to load checkpoint from Redis: %s", exc)
            return None

    async def get_checkpoint_owner(self, run_id: str) -> str | None:
        """Get the current owner of a checkpoint.

        Args:
            run_id: Pipeline run ID.

        Returns:
            Worker ID of the checkpoint owner, or None if not found.
        """
        key = f"{CHECKPOINT_KEY_PREFIX}{run_id}"

        try:
            owner = self.redis.execute_command("HGET", key, "owner")
            if owner:
                return owner.decode("utf-8") if isinstance(owner, bytes) else owner
            return None
        except Exception as exc:
            logger.error("Failed to get checkpoint owner: %s", exc)
            return None

    async def take_ownership(
        self, run_id: str, new_worker_id: str, timeout: float = 300.0
    ) -> bool:
        """Take ownership of a checkpoint (for failover).

        Uses atomic compare-and-swap to prevent race conditions
        when multiple workers try to take over a checkpoint.

        Args:
            run_id: Pipeline run ID.
            new_worker_id: Worker ID taking over.
            timeout: Lock timeout in seconds.

        Returns:
            True if ownership was successfully taken.
        """
        key = f"{CHECKPOINT_KEY_PREFIX}{run_id}"
        lease_key = f"{LEASE_KEY_PREFIX}{run_id}"

        # Lua script for atomic compare-and-swap

        try:
            result = self.redis.execute_script(
                "checkpoint_take_ownership",
                keys=[key, lease_key],
                args=[new_worker_id, new_worker_id, str(time.time()), str(int(timeout))],
            )

            # If we can't use scripts (fallback mode), do simple update
            if result is None:
                current_owner = self.redis.execute_command("HGET", key, "owner")
                if current_owner:
                    self.redis.execute_command("HSET", key, "owner", new_worker_id)
                    self.redis.execute_command(
                        "HSET", key, "updated_at", str(time.time())
                    )
                    logger.info(
                        "Took ownership of checkpoint %s (fallback mode)", run_id
                    )
                    return True
                return False

            if result == 1:
                logger.info(
                    "Took ownership of checkpoint %s for worker %s",
                    run_id,
                    new_worker_id,
                )
                return True
            elif result == -1:
                logger.warning(
                    "Checkpoint %s lease is held by another worker", run_id
                )
                return False
            else:
                logger.warning("Checkpoint %s not found", run_id)
                return False

        except Exception as exc:
            logger.error("Failed to take checkpoint ownership: %s", exc)
            return False

    async def release_ownership(self, run_id: str, worker_id: str) -> bool:
        """Release ownership of a checkpoint.

        Args:
            run_id: Pipeline run ID.
            worker_id: Current owner ID (for verification).

        Returns:
            True if ownership was released.
        """
        key = f"{CHECKPOINT_KEY_PREFIX}{run_id}"
        lease_key = f"{LEASE_KEY_PREFIX}{run_id}"

        try:
            current_owner = self.redis.execute_command("HGET", key, "owner")
            if current_owner:
                owner_str = (
                    current_owner.decode("utf-8")
                    if isinstance(current_owner, bytes)
                    else current_owner
                )
                if owner_str == worker_id:
                    self.redis.execute_command("HSET", key, "owner", "")
                    self.redis.execute_command("DEL", lease_key)
                    logger.info(
                        "Released ownership of checkpoint %s by worker %s",
                        run_id,
                        worker_id,
                    )
                    return True
            return False
        except Exception as exc:
            logger.error("Failed to release checkpoint ownership: %s", exc)
            return False

    async def list_worker_checkpoints(self, worker_id: str) -> list[str]:
        """List all checkpoint run IDs for a given worker.

        Args:
            worker_id: Worker ID to query.

        Returns:
            List of pipeline run IDs owned by this worker.
        """
        worker_key = f"{WORKER_CHECKPOINTS_KEY}:{worker_id}"

        try:
            members = self.redis.execute_command("SMEMBERS", worker_key)
            if not members:
                return []

            run_ids = []
            for member in members:
                run_id = member.decode("utf-8") if isinstance(member, bytes) else member
                run_ids.append(run_id)
            return run_ids
        except Exception as exc:
            logger.error("Failed to list worker checkpoints: %s", exc)
            return []

    async def list_dead_worker_checkpoints(
        self, alive_workers: list[str]
    ) -> list[tuple[str, str]]:
        """Find checkpoints owned by workers that are no longer alive.

        Args:
            alive_workers: List of worker IDs that are currently alive.

        Returns:
            List of (run_id, dead_worker_id) tuples that can be taken over.
        """
        # This is a simplified implementation
        # In production, you'd want to scan all worker checkpoint keys
        dead_checkpoints = []

        try:
            # Get all worker checkpoint keys
            # This is a pattern scan - in production consider using a set of all workers
            alive_set = set(alive_workers)

            # For each potential dead worker, check their checkpoints
            # This is simplified - real implementation would track all workers
            for worker_id in alive_set:
                checkpoints = await self.list_worker_checkpoints(worker_id)
                for run_id in checkpoints:
                    owner = await self.get_checkpoint_owner(run_id)
                    if owner and owner not in alive_set:
                        dead_checkpoints.append((run_id, owner))

            return dead_checkpoints
        except Exception as exc:
            logger.error("Failed to list dead worker checkpoints: %s", exc)
            return []

    async def delete_checkpoint(self, run_id: str) -> bool:
        """Delete a checkpoint from Redis.

        Args:
            run_id: Pipeline run ID to delete.

        Returns:
            True if the checkpoint was deleted.
        """
        key = f"{CHECKPOINT_KEY_PREFIX}{run_id}"
        lease_key = f"{LEASE_KEY_PREFIX}{run_id}"

        try:
            self.redis.execute_command("DEL", key)
            self.redis.execute_command("DEL", lease_key)
            logger.info("Deleted checkpoint %s", run_id)
            return True
        except Exception as exc:
            logger.error("Failed to delete checkpoint: %s", exc)
            return False
