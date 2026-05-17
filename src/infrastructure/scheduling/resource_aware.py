"""Resource-aware scheduler for matching tasks to workers.

Implements intelligent task-to-worker matching based on resource requirements,
worker capabilities, and current load. Enables efficient utilization of
heterogeneous hardware in a local-mesh setup (e.g., powerful desktops
handling browser tasks, RPi handling light probing).
"""

import logging
from typing import Any, cast

from src.infrastructure.queue.models import (
    Job,
    TaskResourceRequirement,
    WorkerInfo,
)

logger = logging.getLogger(__name__)


class ResourceAwareScheduler:
    """Schedules jobs based on worker resource availability and capabilities.

    Maintains a registry of available workers with their resource profiles
    and matches incoming jobs to the most suitable worker based on
    resource requirements and current load.

    Attributes:
        workers: Dict mapping worker_id to WorkerInfo.
        _lock: Thread lock for thread-safe worker updates.
    """

    def __init__(self) -> None:
        """Initialize the scheduler with an empty worker registry."""
        self.workers: dict[str, WorkerInfo] = {}
        self._lock = False  # Simple flag; use threading.Lock() in production

    def update_worker(self, worker_id: str, info: WorkerInfo) -> None:
        """Update worker information in the registry.

        Args:
            worker_id: Unique identifier for the worker.
            info: WorkerInfo instance with current state and resources.
        """
        self.workers[worker_id] = info
        logger.debug(
            "Updated worker %s: status=%s, active_jobs=%d, RAM=%dMB",
            worker_id,
            info.status,
            len(info.active_jobs),
            info.resources.available_ram_mb if info.resources else 0,
        )

    def remove_worker(self, worker_id: str) -> None:
        """Remove a worker from the registry (e.g., on shutdown).

        Args:
            worker_id: Unique identifier for the worker to remove.
        """
        if worker_id in self.workers:
            del self.workers[worker_id]
            logger.info("Removed worker %s from scheduler registry", worker_id)

    def select_worker(self, job: Job) -> str | None:
        """Select the best worker for a job based on resource requirements.

        Evaluates all eligible workers and returns the one with the highest
        suitability score. Considers resource requirements, capabilities,
        and current load.

        Args:
            job: Job instance to be scheduled.

        Returns:
            Worker ID of the selected worker, or None if no suitable worker found.
        """
        requirements = TaskResourceRequirement.for_task_type(job.type)
        candidates: list[tuple[float, str]] = []

        for worker_id, worker in self.workers.items():
            if self._can_handle(worker, requirements):
                score = self._calculate_score(worker, requirements)
                candidates.append((score, worker_id))
                logger.debug(
                    "Worker %s is eligible for job %s (type=%s), score=%.2f",
                    worker_id,
                    job.id,
                    job.type,
                    score,
                )

        if not candidates:
            logger.warning(
                "No eligible worker found for job %s (type=%s, requirements=%s)",
                job.id,
                job.type,
                requirements.model_dump(mode="json"),
            )
            return None

        # Sort by score (higher is better) and return the best worker
        candidates.sort(reverse=True)
        selected_worker_id = candidates[0][1]
        logger.info(
            "Selected worker %s for job %s (type=%s, score=%.2f)",
            selected_worker_id,
            job.id,
            job.type,
            candidates[0][0],
        )
        return selected_worker_id

    def _can_handle(self, worker: WorkerInfo, req: TaskResourceRequirement) -> bool:
        """Check if a worker can handle the given resource requirements.

        Args:
            worker: WorkerInfo instance to evaluate.
            req: TaskResourceRequirement to check against.

        Returns:
            True if the worker can handle the task.
        """
        # Check worker status
        if worker.status not in ("idle", "busy"):
            logger.debug("Worker %s cannot handle task: status=%s", worker.id, worker.status)
            return False

        # Check resource profile exists
        if not worker.resources:
            logger.debug("Worker %s has no resource profile", worker.id)
            return False

        # Check CPU requirements
        if worker.resources.cpu_count < req.min_cpu_cores:
            logger.debug(
                "Worker %s insufficient CPU: has=%d, requires=%d",
                worker.id,
                worker.resources.cpu_count,
                req.min_cpu_cores,
            )
            return False

        # Check RAM requirements (use available RAM, not total)
        if worker.resources.available_ram_mb < req.min_ram_mb:
            logger.debug(
                "Worker %s insufficient RAM: available=%dMB, requires=%dMB",
                worker.id,
                worker.resources.available_ram_mb,
                req.min_ram_mb,
            )
            return False

        # Check browser capability
        if req.requires_browser and "browser" not in worker.capabilities:
            logger.debug("Worker %s missing browser capability for task", worker.id)
            return False

        # Check GPU capability
        if req.requires_gpu and "gpu" not in worker.capabilities:
            logger.debug("Worker %s missing GPU capability for task", worker.id)
            return False

        return True

    def _calculate_score(self, worker: WorkerInfo, req: TaskResourceRequirement) -> float:
        """Calculate a suitability score for a worker (higher is better).

        Considers:
        - Available RAM (more is better)
        - CPU core count (more is better)
        - Current load (fewer active jobs is better)
        - Resource headroom (more spare capacity is better)

        Args:
            worker: WorkerInfo instance to score.
            req: TaskResourceRequirement for the job.

        Returns:
            Float score where higher values indicate better suitability.
        """
        score = 0.0

        if not worker.resources:
            return 0.0

        # RAM score: available RAM contributes positively
        ram_score = worker.resources.available_ram_mb / 1024.0 * 10
        score += ram_score

        # CPU score: more cores = better
        cpu_score = worker.resources.cpu_count * 5.0
        score += cpu_score

        # Load penalty: fewer active jobs = better
        active_jobs_count = len(worker.active_jobs)
        load_penalty = active_jobs_count * 20.0
        score -= load_penalty

        # CPU frequency bonus (if available)
        if worker.resources.cpu_freq_mhz > 0:
            freq_bonus = worker.resources.cpu_freq_mhz / 1000.0 * 2.0
            score += freq_bonus

        # Capacity bonus: if worker has significantly more resources than required
        if worker.resources.cpu_count > req.min_cpu_cores:
            score += 5.0
        if worker.resources.available_ram_mb > req.min_ram_mb * 2:
            score += 5.0

        # Exact capability match bonus
        if req.requires_browser and "browser" in worker.capabilities:
            score += 10.0

        logger.debug(
            "Score for worker %s: total=%.2f (RAM=%.2f, CPU=%.2f, load_penalty=%.2f)",
            worker.id,
            score,
            ram_score,
            cpu_score,
            load_penalty,
        )
        return score

    def get_worker_load(self, worker_id: str) -> dict[str, Any] | None:
        """Get the current load information for a worker.

        Args:
            worker_id: Unique identifier for the worker.

        Returns:
            Dict with load information, or None if worker not found.
        """
        worker = self.workers.get(worker_id)
        if not worker:
            return None

        return {
            "worker_id": worker.id,
            "status": worker.status,
            "active_jobs": len(worker.active_jobs),
            "concurrency": worker.concurrency,
            "cpu_count": worker.resources.cpu_count if worker.resources else 0,
            "available_ram_mb": worker.resources.available_ram_mb if worker.resources else 0,
            "load_percentage": (len(worker.active_jobs) / worker.concurrency * 100)
            if worker.concurrency > 0
            else 0,
        }

    def get_all_workers_summary(self) -> list[dict[str, Any]]:
        """Get a summary of all registered workers and their load.

        Returns:
            List of dicts with worker load information.
        """
        return [
            cast(dict[str, Any], self.get_worker_load(worker_id))
            for worker_id in self.workers
            if self.get_worker_load(worker_id) is not None
        ]
