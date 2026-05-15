"""Concurrent execution engine for the cyber security test pipeline.

Provides DAG-based task scheduling, resource-pool-backed concurrency limiting,
dynamic load balancing, and support for both CPU-bound and I/O-bound workloads.

Public API exports:
    - Task, TaskResult, TaskStatus, TaskPriority, ResourcePool, ExecutionConfig
    - ResourcePoolManager
    - ConcurrentExecutor, ExecutionSummary
    - LoadBalancer, WorkerStats
    - DEFAULT_EXECUTION_CONFIG, load_execution_config
"""

from src.infrastructure.execution_engine.concurrent_executor import (
    ConcurrentExecutor,
    ExecutionSummary,
)
from src.infrastructure.execution_engine.config import (
    DEFAULT_EXECUTION_CONFIG,
    ExecutionConfig,
    load_execution_config,
)
from src.infrastructure.execution_engine.load_balancer import LoadBalancer, WorkerStats
from src.infrastructure.execution_engine.models import (
    ExecutionConfig as ExecutionConfigModel,
)
from src.infrastructure.execution_engine.models import (
    ResourcePool as ResourcePoolModel,
)
from src.infrastructure.execution_engine.models import (
    Task,
    TaskPriority,
    TaskResult,
    TaskStatus,
)
from src.infrastructure.execution_engine.resource_pool import ResourcePool, ResourcePoolManager

__all__ = [
    # Models
    "Task",
    "TaskResult",
    "TaskStatus",
    "TaskPriority",
    "ResourcePool",
    "ResourcePoolModel",
    "ExecutionConfig",
    "ExecutionConfigModel",
    # Resource pool
    "ResourcePool",
    "ResourcePoolManager",
    # Executor
    "ConcurrentExecutor",
    "ExecutionSummary",
    # Load balancer
    "LoadBalancer",
    "WorkerStats",
    # Config
    "DEFAULT_EXECUTION_CONFIG",
    "load_execution_config",
]
