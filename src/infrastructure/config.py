"""Infrastructure configuration models.

Provides configuration classes for various infrastructure components
including local-mesh orchestration settings.
"""

from pydantic import BaseModel, Field


class LocalMeshConfig(BaseModel):
    """Configuration for local-mesh orchestration.

    Controls P2P worker discovery, resource-aware scheduling,
    and cross-node checkpoint replication behavior.

    Attributes:
        enable_mdns_discovery: Use mDNS for worker discovery (default True).
        mdns_port: Port for mDNS service registration.
        heartbeat_interval: Seconds between worker heartbeats.
        worker_timeout: Seconds without heartbeat before worker is dead.
        checkpoint_replication: Enable Redis-based checkpoint replication.
        auto_failover: Automatically take over checkpoints from dead workers.
        resource_check_interval: Seconds between resource profile updates.
        scheduler_enabled: Use resource-aware scheduling for task assignment.
    """

    enable_mdns_discovery: bool = Field(
        default=True,
        description="Use mDNS for P2P worker discovery",
    )
    mdns_port: int = Field(
        default=8008,
        ge=1024,
        le=65535,
        description="Port for mDNS service registration",
    )
    heartbeat_interval: float = Field(
        default=15.0,
        gt=0,
        description="Seconds between worker heartbeats",
    )
    worker_timeout: float = Field(
        default=60.0,
        gt=0,
        description="Seconds without heartbeat before worker is considered dead",
    )
    checkpoint_replication: bool = Field(
        default=True,
        description="Enable Redis-based checkpoint replication",
    )
    auto_failover: bool = Field(
        default=True,
        description="Automatically take over checkpoints from dead workers",
    )
    resource_check_interval: float = Field(
        default=30.0,
        gt=0,
        description="Seconds between resource profile updates",
    )
    scheduler_enabled: bool = Field(
        default=True,
        description="Use resource-aware scheduling for task assignment",
    )


class QueueExtensionConfig(BaseModel):
    """Extended configuration for the job queue with mesh support.

    Attributes:
        queue_name: Name of the queue.
        redis_url: Redis connection URL (None for in-memory).
        enable_scheduler: Use the resource-aware scheduler.
        scheduler_refresh_interval: How often to refresh worker states.
    """

    queue_name: str = Field(default="security-pipeline")
    redis_url: str | None = Field(default=None)
    enable_scheduler: bool = Field(default=True)
    scheduler_refresh_interval: float = Field(
        default=10.0,
        gt=0,
        description="Seconds between scheduler worker list refreshes",
    )


def load_mesh_config(config_dict: dict | None = None) -> LocalMeshConfig:
    """Load LocalMeshConfig from a dictionary.

    Args:
        config_dict: Optional dictionary with configuration values.

    Returns:
        LocalMeshConfig instance.
    """
    if config_dict is None:
        return LocalMeshConfig()
    return LocalMeshConfig(**config_dict)


def load_queue_extension_config(config_dict: dict | None = None) -> QueueExtensionConfig:
    """Load QueueExtensionConfig from a dictionary.

    Args:
        config_dict: Optional dictionary with configuration values.

    Returns:
        QueueExtensionConfig instance.
    """
    if config_dict is None:
        return QueueExtensionConfig()
    return QueueExtensionConfig(**config_dict)
