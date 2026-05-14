"""Pydantic models for the concurrent execution engine.

Defines the core data structures:
    - Task: immutable task description with dependencies, priority, resource requirements
    - TaskResult: outcome of task execution
    - ResourcePool: capacity and limits for a resource type
    - ExecutionConfig: top-level configuration for the engine
"""

import enum
import uuid
from collections.abc import Callable
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class TaskPriority(int, enum.Enum):
    """Priority levels for task scheduling.

    Lower numeric value = higher priority.
    """

    CRITICAL = 0
    HIGH = 1
    NORMAL = 2
    LOW = 3
    BACKGROUND = 4


class TaskStatus(enum.StrEnum):
    """Lifecycle states for a task."""

    PENDING = "pending"
    QUEUED = "queued"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMED_OUT = "timed_out"
    SKIPPED = "skipped"


class Task(BaseModel):
    """Immutable description of a unit of work.

    Attributes:
        id: Unique identifier (auto-generated UUID if not provided).
        name: Human-readable task name.
        fn: Callable to execute. May be sync or async.
        args: Positional arguments for fn.
        kwargs: Keyword arguments for fn.
        priority: Scheduling priority (lower = higher priority).
        dependencies: Set of task IDs that must complete before this task runs.
        resource_types: Resource pool keys required to run this task.
        timeout_seconds: Maximum wall-clock time for execution.
        retries: Number of retry attempts on failure.
        retry_delay_seconds: Base delay between retries (exponential backoff).
        tags: Arbitrary labels for filtering/grouping.
        cpu_bound: If True, the task will be dispatched to a ProcessPoolExecutor.
        metadata: Free-form dict for caller-specific context.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    fn: Callable[..., Any]
    args: tuple[Any, ...] = Field(default_factory=tuple)
    kwargs: dict[str, Any] = Field(default_factory=dict)
    priority: TaskPriority = TaskPriority.NORMAL
    dependencies: set[str] = Field(default_factory=set)
    resource_types: list[str] = Field(default_factory=lambda: ["default"])
    timeout_seconds: float = 120.0
    retries: int = 0
    retry_delay_seconds: float = 1.0
    tags: list[str] = Field(default_factory=list)
    cpu_bound: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)

    def __hash__(self) -> int:
        return hash(self.id)


class TaskResult(BaseModel):
    """Outcome of executing a single task.

    Attributes:
        task_id: The ID of the task this result belongs to.
        task_name: Human-readable task name (copied for convenience).
        status: Final status after execution.
        result: Return value of fn on success (None otherwise).
        error: Error message on failure (None on success).
        exception: The actual exception object (not serialised).
        duration_seconds: Wall-clock time from start to finish.
        attempts: Number of execution attempts (1 + retries used).
        worker_id: Identifier of the worker that executed the task.
        started_at: Monotonic timestamp when execution began.
        finished_at: Monotonic timestamp when execution ended.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    task_id: str
    task_name: str
    status: TaskStatus
    result: Any = None
    error: str | None = None
    exception: BaseException | None = None
    duration_seconds: float = 0.0
    attempts: int = 1
    worker_id: str | None = None
    started_at: float = 0.0
    finished_at: float = 0.0

    @property
    def success(self) -> bool:
        """True if the task completed successfully."""
        return self.status == TaskStatus.SUCCESS

    @property
    def failed(self) -> bool:
        """True if the task ended in any non-success state."""
        return self.status not in (TaskStatus.SUCCESS, TaskStatus.SKIPPED)


class ResourcePool(BaseModel):
    """Capacity definition for a single resource type.

    Attributes:
        name: Unique pool identifier (e.g. "cpu", "network", "external_tools").
        max_concurrent: Hard upper bound on simultaneous holders.
        current_usage: Number of active holders (runtime-only, not persisted).
        min_size: Minimum pool size for dynamic scaling.
        max_size: Maximum pool size for dynamic scaling.
        acquire_timeout_seconds: How long to wait for a resource before failing.
        health_check_interval_seconds: Interval between health checks.
    """

    name: str
    max_concurrent: int = 10
    current_usage: int = 0
    min_size: int = 1
    max_size: int = 50
    acquire_timeout_seconds: float = 30.0
    health_check_interval_seconds: float = 60.0


class ExecutionConfig(BaseModel):
    """Top-level configuration for the concurrent execution engine.

    Attributes:
        max_workers: Default maximum number of concurrent tasks (I/O-bound).
        max_cpu_workers: Maximum number of concurrent CPU-bound tasks.
        default_timeout_seconds: Fallback timeout when a task does not specify one.
        default_retries: Fallback retry count when a task does not specify one.
        resource_pools: Mapping of pool name -> ResourcePool definition.
        enable_load_balancing: Whether to dynamically distribute load across workers.
        load_balancer_sample_interval_seconds: How often to sample worker load.
        load_balancer_adjustment_interval_seconds: How often to adjust concurrency.
        enable_progress_callbacks: Whether to invoke progress callbacks.
        result_aggregation_mode: "all" to collect every result, "success_only" to
            discard failures, "first_error" to stop after the first failure.
        cancel_on_first_error: If True, cancel all pending/running tasks on first error.
        shutdown_timeout_seconds: Maximum time to wait for graceful shutdown.
    """

    max_workers: int = 20
    max_cpu_workers: int = 4
    default_timeout_seconds: float = 120.0
    default_retries: int = 0
    resource_pools: dict[str, ResourcePool] = Field(
        default_factory=lambda: {
            "default": ResourcePool(name="default", max_concurrent=20),
            "network": ResourcePool(name="network", max_concurrent=50),
            "cpu": ResourcePool(name="cpu", max_concurrent=4),
            "external_tools": ResourcePool(name="external_tools", max_concurrent=10),
        }
    )
    enable_load_balancing: bool = True
    load_balancer_sample_interval_seconds: float = 5.0
    load_balancer_adjustment_interval_seconds: float = 15.0
    enable_progress_callbacks: bool = True
    result_aggregation_mode: str = "all"
    cancel_on_first_error: bool = False
    shutdown_timeout_seconds: float = 30.0
