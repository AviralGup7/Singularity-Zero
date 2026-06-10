"""Task execution handlers for the queue worker.

Provides job processing with error isolation, tracing, and cancellation support.
"""

from __future__ import annotations

import asyncio
import time
import traceback
from typing import Any

from src.core.frontier.tracing_manager import get_tracing_manager
from src.core.logging.trace_logging import get_pipeline_logger
from src.infrastructure.queue.models import Job

logger = get_pipeline_logger(__name__)


class WorkerTaskHandlersMixin:
    """Mixin providing task/job execution handlers."""

    async def _process_job(self, job: Job) -> None:
        """Process a single job with error isolation."""
        task_cancelled = False

        async def check_cancelled() -> None:
            nonlocal task_cancelled
            while self._running:
                if await self.queue.is_job_cancelled(job.id):
                    logger.warning("Job %s was cancelled by user, terminating task", job.id)
                    task_cancelled = True
                    return
                await asyncio.sleep(2.0)

        cancel_checker: asyncio.Task[None] | None = None
        cancel_checker = asyncio.create_task(check_cancelled())

        job.mark_running()
        self._info.status = "busy"
        self._info.active_jobs.append(job.id)

        job_key = f"queue:{self.queue.queue_name}:job:{job.id}"
        self.queue.redis.execute_command(
            "HSET",
            job_key,
            "state",
            "running",
            "started_at",
            str(time.time()),
            "worker_id",
            self.worker_id,
        )

        try:
            handler = self.handler or self.queue.get_handler(job.type)
            if handler is None:
                from src.infrastructure.queue.plugin_handler_bridge import (
                    resolve_handler_for_job_type,
                )

                handler = resolve_handler_for_job_type(self.queue, job.type)
            if handler is None:
                raise ValueError(f"No handler registered for job type: {job.type}")

            if not isinstance(job.payload, dict) or not job.payload.get("schema_version"):
                error_msg = (
                    f"Job {job.id} rejected: payload is not a valid TaskEnvelope. "
                    "All queue payloads must be TaskEnvelope instances."
                )
                logger.error(error_msg)
                await self.queue.fail_job(job.id, self.worker_id, error_msg)
                return

            envelope = job.as_task_envelope()
            handler_input: Any = envelope

            if not isinstance(envelope.type, str) or not envelope.type:
                logger.error(
                    "Job %s rejected: invalid TaskEnvelope type '%s' "
                    "(missing or non-string). "
                    "All queue payloads must be TaskEnvelope instances.",
                    job.id,
                    getattr(envelope, "type", None),
                )
                await self.queue.fail_job(
                    job.id,
                    self.worker_id,
                    "Invalid TaskEnvelope: missing or empty type field",
                )
                return

            tracer = get_tracing_manager()
            parent_headers = tracer.extract_task_headers(envelope)
            with tracer.start_span(
                f"queue.worker.{envelope.type}",
                parent_headers=parent_headers,
                attributes={
                    "stage_name": envelope.type,
                    "job_id": job.id,
                    "queue_name": self.queue.queue_name,
                    "worker_id": self.worker_id,
                    "target_count": 1,
                    "scope_size": 0,
                },
            ) as span:
                if asyncio.iscoroutinefunction(handler):
                    result_task = asyncio.create_task(handler(handler_input))
                else:
                    result_task = asyncio.create_task(asyncio.to_thread(handler, handler_input))

                while not result_task.done() and not task_cancelled:
                    await asyncio.sleep(0.5)

                if task_cancelled:
                    if not result_task.done():
                        result_task.cancel()
                    logger.info("Worker aborted job %s due to cancellation", job.id)
                    return

                result = await result_task
                span.set_attribute("status", "OK")

            await self.queue.complete_job(job.id, self.worker_id, result)
            self._info.total_processed += 1
            logger.info("Job %s completed successfully (type=%s)", job.id, job.type)

        except Exception as exc:
            if task_cancelled:
                return
            error_msg = f"{type(exc).__name__}: {exc}\n{traceback.format_exc()}"
            logger.error("Job %s failed (type=%s): %s", job.id, job.type, exc)

            success, outcome = await self.queue.fail_job(job.id, self.worker_id, error_msg)

            if outcome == "dead_letter":
                logger.warning(
                    "Job %s moved to dead-letter queue after %d retries",
                    job.id,
                    job.retries,
                )
            self._info.total_failed += 1

        finally:
            if cancel_checker is not None:
                cancel_checker.cancel()
                try:
                    await cancel_checker
                except asyncio.CancelledError as exc:
                    logger.warning("Operation failed in task_handlers.py: %s", exc, exc_info=True)  # noqa: BLE001
            if job.id in self._info.active_jobs:
                self._info.active_jobs.remove(job.id)

            if len(self._info.active_jobs) == 0:
                self._info.status = "idle"
