"""Infrastructure checkpoint module.

Provides distributed checkpoint storage using Redis
for cross-node replication and failover.
"""

from .distributed import CHECKPOINT_KEY_PREFIX, LEASE_KEY_PREFIX, DistributedCheckpointStore

__all__ = ["DistributedCheckpointStore", "CHECKPOINT_KEY_PREFIX", "LEASE_KEY_PREFIX"]
