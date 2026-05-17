"""Pydantic models for the distributed job queue system.

Defines core data models including Job, JobState enum, WorkerInfo, and
QueueConfig with full type safety and validation.
"""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

try:
    import psutil
except ImportError:
    psutil = None

from pydantic import BaseModel, Field

from src.core.contracts.task_envelope import TASK_ENVELOPE_VERSION, TaskEnvelope
from src.core.logging.trace_logging import get_pipeline_logger

logger = get_pipeline_logger(__name__)


class ResourceProfile(BaseModel):
    """System resource information for a worker."""

    cpu_count: int = Field(
        default_factory=lambda: (psutil.cpu_count(logical=True) if psutil else 1) or 1
    )
    cpu_freq_mhz: float = Field(
        default_factory=lambda: psutil.cpu_freq().max if psutil and psutil.cpu_freq() else 0.0
    )
    total_ram_mb: int = Field(
        default_factory=lambda: psutil.virtual_memory().total // 1024 // 1024 if psutil else 0
    )
    available_ram_mb: int = Field(
        default_factory=lambda: psutil.virtual_memory().available // 1024 // 1024 if psutil else 0
    )
    disk_gb_free: float = Field(
        default_factory=lambda: psutil.disk_usage("/").free / (1024**3) if psutil else 0.0
    )
    platform: str = Field(default_factory=lambda: __import__("platform").system())
    python_version: str = Field(default_factory=lambda: __import__("platform").python_version())

    @classmethod
    def detect(cls) -> ResourceProfile:
        """Detect current system resources."""
        import platform

        if psutil:
            try:
                cpu_freq = psutil.cpu_freq()
                mem = psutil.virtual_memory()
                disk = psutil.disk_usage("/")

                return cls(
                    cpu_count=psutil.cpu_count(logical=True) or 1,
                    cpu_freq_mhz=cpu_freq.max if cpu_freq else 0.0,
                    total_ram_mb=mem.total // 1024 // 1024,
                    available_ram_mb=mem.available // 1024 // 1024,
                    disk_gb_free=disk.free / (1024**3),
                    platform=platform.system(),
                    python_version=platform.python_version(),
                )
            except Exception:
                logger.debug("psutil detection failed", exc_info=True)
                pass

        return cls(
            cpu_count=1,
            cpu_freq_mhz=0.0,
            total_ram_mb=0,
            available_ram_mb=0,
            disk_gb_free=0.0,
            platform=platform.system(),
            python_version=platform.python_version(),
        )


class TaskResourceRequirement(BaseModel):
    """Resource requirements for a task type."""

    min_cpu_cores: int = Field(default=1, ge=1)
    min_ram_mb: int = Field(default=256, ge=128)
    requires_browser: bool = Field(default=False)
    requires_gpu: bool = Field(default=False)
    estimated_duration_seconds: float = Field(default=60.0)

    @classmethod
    def for_task_type(cls, task_type: str) -> TaskResourceRequirement:
        """Return resource requirements based on task type."""
        heavy_tasks = {"headless_browser", "dom_xss", "websocket_hijacking", "screenshot"}
        light_tasks = {"port_probe", "http_methods", "cloud_metadata", "graphql"}

        if task_type in heavy_tasks:
            return cls(min_cpu_cores=2, min_ram_mb=2048, requires_browser=True)
        elif task_type in light_tasks:
            return cls(min_cpu_cores=1, min_ram_mb=256, requires_browser=False)
        return cls()


class JobState(StrEnum):
    """Enumeration of all possible job states in the queue lifecycle.

    State transitions:
        PENDING -> CLAIMED -> RUNNING -> COMPLETED
        PENDING -> CLAIMED -> RUNNING -> FAILED -> RETRYING -> PENDING
        PENDING -> CLAIMED -> RUNNING -> FAILED -> DEAD_LETTER
        PENDING -> CANCELLED
        RETRYING -> DEAD_LETTER (after max retries exhausted)
    """

    PENDING = "pending"
    CLAIMED = "claimed"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    RETRYING = "retrying"
    DEAD_LETTER = "dead_letter"
    CANCELLED = "cancelled"


class Job(BaseModel):
    """Represents a unit of work in the job queue.

    Attributes:
        id: Unique job identifier (UUID4 by default).
        type: Job type string used for routing to appropriate handlers.
        payload: Arbitrary JSON-serializable data for the job handler.
        priority: Priority level (1-10, higher = more urgent). Default 5.
        state: Current state in the job lifecycle.
        retries: Number of retry attempts already performed.
        max_retries: Maximum retry attempts before moving to dead-letter queue.
        created_at: Unix timestamp when the job was enqueued.
        started_at: Unix timestamp when the job began execution (None if not started).
        completed_at: Unix timestamp when the job finished (None if not finished).
        error: Last error message if the job failed.
        worker_id: ID of the worker currently processing or that processed this job.
        result: Arbitrary JSON-serializable result data from job execution.
        metadata: Additional key-value pairs for job context and tracking.
        lease_expires_at: Unix timestamp when the current claim lease expires.
        queue_name: Name of the queue this job belongs to.
    """

    id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    type: str = Field(..., min_length=1, description="Job type for handler routing")
    payload: dict[str, Any] = Field(default_factory=dict)
    priority: int = Field(
        default=5, ge=1, le=10, description="Priority 1-10, higher is more urgent"
    )
    state: JobState = Field(default=JobState.PENDING)
    retries: int = Field(default=0, ge=0)
    max_retries: int = Field(default=3, ge=0)
    created_at: float = Field(default_factory=time.time)
    started_at: float | None = Field(default=None)
    completed_at: float | None = Field(default=None)
    error: str | None = Field(default=None)
    worker_id: str | None = Field(default=None)
    result: dict[str, Any] | None = Field(default=None)
    metadata: dict[str, Any] = Field(default_factory=dict)
    task_schema_version: str = Field(default=TASK_ENVELOPE_VERSION)
    lease_expires_at: float | None = Field(default=None)
    queue_name: str = Field(default="default")

    @classmethod
    def from_task_envelope(
        cls,
        envelope: TaskEnvelope,
        *,
        queue_name: str,
        priority: int = 5,
        max_retries: int = 3,
        job_id: str | None = None,
    ) -> Job:
        """Create a queue job from a canonical task envelope."""
        return cls(
            id=job_id or uuid.uuid4().hex,
            type=envelope.type,
            payload=envelope.to_dict(),
            metadata={
                "correlation_id": envelope.correlation_id,
                **dict(envelope.metadata),
            },
            task_schema_version=envelope.schema_version,
            queue_name=queue_name,
            priority=priority,
            max_retries=max_retries,
        )

    def as_task_envelope(self) -> TaskEnvelope:
        """Return canonical task envelope for this job payload."""
        payload = self.payload or {}
        if isinstance(payload, dict) and payload.get("schema_version"):
            envelope = TaskEnvelope.from_dict(payload)
            metadata_correlation = str(self.metadata.get("correlation_id", "") or "").strip()
            if metadata_correlation and metadata_correlation != envelope.correlation_id:
                return TaskEnvelope(
                    type=envelope.type,
                    payload=dict(envelope.payload),
                    metadata=dict(envelope.metadata),
                    retry_policy=envelope.retry_policy,
                    correlation_id=metadata_correlation,
                    schema_version=envelope.schema_version,
                )
            return envelope
        return TaskEnvelope(
            type=self.type,
            payload=payload,
            metadata=dict(self.metadata),
            correlation_id=str(self.metadata.get("correlation_id", uuid.uuid4().hex)),
            schema_version=self.task_schema_version or TASK_ENVELOPE_VERSION,
        )

    def mark_claimed(self, worker_id: str, lease_seconds: float) -> None:
        """Transition job to CLAIMED state with a lease timeout.

        Args:
            worker_id: ID of the worker claiming this job.
            lease_seconds: Duration in seconds before the lease expires.
        """
        self.state = JobState.CLAIMED
        self.worker_id = worker_id
        self.lease_expires_at = time.time() + lease_seconds

    def mark_running(self) -> None:
        """Transition job from CLAIMED to RUNNING state."""
        self.state = JobState.RUNNING
        self.started_at = time.time()

    def mark_completed(self, result: dict[str, Any] | None = None) -> None:
        """Transition job to COMPLETED state with optional result data.

        Args:
            result: Optional result payload from job execution.
        """
        self.state = JobState.COMPLETED
        self.completed_at = time.time()
        self.result = result
        self.lease_expires_at = None

    def mark_failed(self, error: str) -> None:
        """Transition job to FAILED state with error message.

        Args:
            error: Description of the failure.
        """
        self.state = JobState.FAILED
        self.error = error
        self.lease_expires_at = None

    def mark_retrying(self) -> None:
        """Transition job to RETRYING state, incrementing retry counter."""
        self.retries += 1
        self.state = JobState.RETRYING
        self.worker_id = None
        self.error = None
        self.lease_expires_at = None

    def mark_dead_letter(self) -> None:
        """Transition job to DEAD_LETTER state after exhausting retries."""
        self.state = JobState.DEAD_LETTER
        self.completed_at = time.time()
        self.worker_id = None
        self.lease_expires_at = None

    def mark_cancelled(self) -> None:
        """Transition job to CANCELLED state."""
        self.state = JobState.CANCELLED
        self.completed_at = time.time()
        self.worker_id = None
        self.lease_expires_at = None

    def can_retry(self) -> bool:
        """Check if the job has remaining retry attempts.

        Returns:
            True if retries are available and job is not cancelled.
        """
        return self.retries < self.max_retries and self.state != JobState.CANCELLED

    def is_lease_expired(self) -> bool:
        """Check if the current claim lease has expired.

        Returns:
            True if the lease has expired or no lease is set.
        """
        if self.lease_expires_at is None:
            return False
        return time.time() > self.lease_expires_at

    def to_redis_hash(self) -> dict[str, str]:
        """Serialize job to a Redis hash-compatible string dict.

        Returns:
            Dict with string keys and string values suitable for Redis HSET.
        """
        import json

        return {
            "id": self.id,
            "type": self.type,
            "payload": json.dumps(self.payload),
            "priority": str(self.priority),
            "state": self.state.value,
            "retries": str(self.retries),
            "max_retries": str(self.max_retries),
            "created_at": str(self.created_at),
            "started_at": str(self.started_at) if self.started_at is not None else "",
            "completed_at": str(self.completed_at) if self.completed_at is not None else "",
            "error": self.error or "",
            "worker_id": self.worker_id or "",
            "result": json.dumps(self.result) if self.result is not None else "",
            "metadata": json.dumps(self.metadata),
            "task_schema_version": self.task_schema_version,
            "lease_expires_at": str(self.lease_expires_at)
            if self.lease_expires_at is not None
            else "",
            "queue_name": self.queue_name,
        }

    @classmethod
    def from_redis_hash(cls, data: dict[bytes | str, bytes | str]) -> Job:
        """Deserialize a Job from a Redis hash response.

        Args:
            data: Dict from Redis HGETALL with bytes or string keys/values.

        Returns:
            Reconstructed Job instance.
        """
        import json

        def decode(val: bytes | str) -> str:
            return val.decode("utf-8") if isinstance(val, bytes) else val

        def decode_opt(val: bytes | str) -> str | None:
            s = decode(val)
            return s if s else None

        def decode_json(val: bytes | str) -> Any:
            s = decode(val)
            return json.loads(s) if s else {}

        def decode_json_opt(val: bytes | str) -> Any | None:
            s = decode(val)
            return json.loads(s) if s else None

        normalized: dict[str, bytes | str] = {}
        for raw_key, raw_value in data.items():
            key = raw_key.decode("utf-8") if isinstance(raw_key, bytes) else str(raw_key)
            normalized[key] = raw_value

        return cls(
            id=decode(normalized.get("id", b"")),
            type=decode(normalized.get("type", b"")),
            payload=decode_json(normalized.get("payload", b"{}")),
            priority=int(decode(normalized.get("priority", "5"))),
            state=JobState(decode(normalized.get("state", "pending"))),
            retries=int(decode(normalized.get("retries", "0"))),
            max_retries=int(decode(normalized.get("max_retries", "3"))),
            created_at=float(decode(normalized.get("created_at", "0"))),
            started_at=float(decode(normalized["started_at"]))
            if normalized.get("started_at")
            else None,
            completed_at=float(decode(normalized["completed_at"]))
            if normalized.get("completed_at")
            else None,
            error=decode_opt(normalized.get("error", b"")),
            worker_id=decode_opt(normalized.get("worker_id", b"")),
            result=decode_json_opt(normalized.get("result", b"")),
            metadata=decode_json(normalized.get("metadata", b"{}")),
            task_schema_version=decode(
                normalized.get("task_schema_version", TASK_ENVELOPE_VERSION)
            ),
            lease_expires_at=float(decode(normalized["lease_expires_at"]))
            if normalized.get("lease_expires_at")
            else None,
            queue_name=decode(normalized.get("queue_name", b"default")),
        )


class WorkerInfo(BaseModel):
    """Information about a registered queue worker.

    Attributes:
        id: Unique worker identifier.
        hostname: Hostname or machine name of the worker.
        pid: Process ID of the worker.
        status: Current worker status (idle, busy, shutting_down, dead).
        concurrency: Maximum number of jobs this worker can process simultaneously.
        active_jobs: List of job IDs currently being processed.
        last_heartbeat: Unix timestamp of the last heartbeat signal.
        started_at: Unix timestamp when the worker started.
        total_processed: Total number of jobs successfully processed.
        total_failed: Total number of jobs that failed during processing.
        metadata: Additional worker metadata (capabilities, version, etc.).
        resources: System resource information detected at startup.
        capabilities: List of capability tags (e.g., ["browser", "heavy_compute"]).
    """

    id: str = Field(..., min_length=1)
    hostname: str = Field(default="unknown")
    pid: int = Field(default=0)
    status: str = Field(default="idle")
    concurrency: int = Field(default=1, ge=1)
    active_jobs: list[str] = Field(default_factory=list)
    last_heartbeat: float = Field(default_factory=time.time)
    started_at: float = Field(default_factory=time.time)
    total_processed: int = Field(default=0, ge=0)
    total_failed: int = Field(default=0, ge=0)
    metadata: dict[str, Any] = Field(default_factory=dict)
    resources: ResourceProfile = Field(default_factory=ResourceProfile.detect)
    capabilities: list[str] = Field(default_factory=list)

    def is_alive(self, timeout_seconds: float = 30.0) -> bool:
        """Check if the worker is considered alive based on heartbeat.

        Args:
            timeout_seconds: Seconds without heartbeat before marking as dead.

        Returns:
            True if the worker has sent a heartbeat within the timeout.
        """
        return time.time() - self.last_heartbeat < timeout_seconds

    def to_redis_hash(self) -> dict[str, str]:
        """Serialize worker info to a Redis hash-compatible string dict.

        Returns:
            Dict with string keys and string values suitable for Redis HSET.
        """
        import json

        return {
            "id": self.id,
            "hostname": self.hostname,
            "pid": str(self.pid),
            "status": self.status,
            "concurrency": str(self.concurrency),
            "active_jobs": json.dumps(self.active_jobs),
            "last_heartbeat": str(self.last_heartbeat),
            "started_at": str(self.started_at),
            "total_processed": str(self.total_processed),
            "total_failed": str(self.total_failed),
            "metadata": json.dumps(self.metadata),
            "resources": json.dumps(
                self.resources.to_dict() if hasattr(self.resources, "to_dict") else {}
            ),
            "capabilities": json.dumps(self.capabilities),
        }

    @classmethod
    def from_redis_hash(cls, data: dict[bytes | str, bytes | str]) -> WorkerInfo:
        """Deserialize WorkerInfo from a Redis hash response.

        Args:
            data: Dict from Redis HGETALL with bytes or string keys/values.

        Returns:
            Reconstructed WorkerInfo instance.
        """
        import json

        def decode(val: bytes | str) -> str:
            return val.decode("utf-8") if isinstance(val, bytes) else val

        def decode_json(val: bytes | str) -> Any:
            s = decode(val)
            return json.loads(s) if s else []

        def decode_json_obj(val: bytes | str) -> Any:
            s = decode(val)
            return json.loads(s) if s else {}

        return cls(
            id=decode(data.get("id", b"")),
            hostname=decode(data.get("hostname", b"unknown")),
            pid=int(decode(data.get("pid", "0"))),
            status=decode(data.get("status", b"idle")),
            concurrency=int(decode(data.get("concurrency", "1"))),
            active_jobs=decode_json(data.get("active_jobs", b"[]")),
            last_heartbeat=float(decode(data.get("last_heartbeat", "0"))),
            started_at=float(decode(data.get("started_at", "0"))),
            total_processed=int(decode(data.get("total_processed", "0"))),
            total_failed=int(decode(data.get("total_failed", "0"))),
            metadata=decode_json_obj(data.get("metadata", b"{}")),
            resources=ResourceProfile(**decode_json_obj(data.get("resources", b"{}"))),
            capabilities=decode_json(data.get("capabilities", b"[]")),
        )


class QueueConfig(BaseModel):
    """Configuration for the job queue system.

    Attributes:
        redis_url: Redis connection URL. Falls back to in-memory if None.
        redis_db: Redis database number (0-15).
        redis_max_connections: Maximum connections in the connection pool.
        queue_name: Default queue name for job routing.
        default_priority: Default priority for new jobs (1-10).
        default_max_retries: Default max retries for new jobs.
        lease_seconds: Duration in seconds for job claim leases.
        lease_check_interval: Seconds between stale lease cleanup checks.
        heartbeat_interval: Seconds between worker heartbeat signals.
        worker_timeout: Seconds without heartbeat before worker is considered dead.
        dead_letter_queue_name: Name of the dead-letter queue.
        enable_metrics: Whether to collect and store queue metrics.
        metrics_ttl: TTL in seconds for metrics data in Redis.
    """

    redis_url: str | None = Field(default=None)
    redis_db: int = Field(default=0, ge=0, le=15)
    redis_max_connections: int = Field(default=20, ge=1)
    queue_name: str = Field(default="default")
    default_priority: int = Field(default=5, ge=1, le=10)
    default_max_retries: int = Field(default=3, ge=0)
    lease_seconds: float = Field(default=300.0, gt=0)
    lease_check_interval: float = Field(default=60.0, gt=0)
    heartbeat_interval: float = Field(default=15.0, gt=0)
    worker_timeout: float = Field(default=30.0, gt=0)
    dead_letter_queue_name: str = Field(default="dead_letter")
    enable_metrics: bool = Field(default=True)
    metrics_ttl: int = Field(default=86400, gt=0)
