"""Execution loop and checkpoint integration for the queue worker.

Provides the main polling loop, startup orchestration, and stale checkpoint takeover.
"""

from __future__ import annotations

import asyncio
from typing import Any

from src.core.logging.trace_logging import get_pipeline_logger

logger = get_pipeline_logger(__name__)


class WorkerExecutionLoopMixin:
    """Mixin providing the main polling loop and stale checkpoint takeover."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self._loop: asyncio.AbstractEventLoop | None = None
        self._running: bool = False
        super().__init__(*args, **kwargs)

    @staticmethod
    def _log_task_exception(task: asyncio.Task[Any]) -> None:
        """Log exceptions from background tasks that would otherwise be silently lost."""
        if task.cancelled():
            return
        exc = task.exception()
        if exc is not None:
            logger.error("Background task %s raised: %s", task.get_name(), exc)

    async def start(self) -> None:
        """Start the worker and begin processing jobs."""
        if self._running:
            logger.warning("Worker %s is already running", self.worker_id)
            return

        self._running = True
        self._shutdown_requested = False
        self._loop = asyncio.get_running_loop()

        await self._register()

        await self._handle_stale_checkpoints()

        heartbeat_task = asyncio.create_task(self._heartbeat())
        heartbeat_task.add_done_callback(self._log_task_exception)

        try:
            await self._poll_and_process()
        except asyncio.CancelledError as exc:
            logger.warning("Operation failed in execution_loop.py: %s", exc, exc_info=True)  # noqa: BLE001
        finally:
            heartbeat_task.cancel()
            try:
                await heartbeat_task
            except asyncio.CancelledError as exc:
                logger.warning("Operation failed in execution_loop.py: %s", exc, exc_info=True)  # noqa: BLE001

            await self._cleanup()
            self._running = False
            logger.info(
                "Worker %s stopped (processed=%d, failed=%d)",
                self.worker_id,
                self._info.total_processed,
                self._info.total_failed,
            )

    async def _poll_and_process(self) -> None:
        """Main processing loop that claims jobs and respects concurrency."""
        while self._running and not self._shutdown_requested:
            try:
                active_count = len(self._info.active_jobs)
                if active_count >= self.concurrency:
                    await asyncio.sleep(self.poll_interval)
                    continue

                if hasattr(self.queue, "get_next_job_for_worker"):
                    job = await self.queue.get_next_job_for_worker(self.worker_id)
                else:
                    job = await self.queue.claim_job(self.worker_id)

                if job is None:
                    await asyncio.sleep(self.poll_interval)
                    continue

                task = asyncio.create_task(self._process_job(job))
                self._active_tasks.add(task)
                task.add_done_callback(self._active_tasks.discard)

            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error("Poll loop error: %s", exc)
                await asyncio.sleep(self.poll_interval)

    async def _handle_stale_checkpoints(self) -> None:
        """Check for checkpoints owned by dead workers and take them over."""
        if not self.distributed_store:
            return

        try:
            workers_key = f"queue:{self.queue.queue_name}:workers"
            alive_workers_data = self.queue.redis.execute_command("SMEMBERS", workers_key)
            alive_workers = set()
            if alive_workers_data:
                for w in alive_workers_data:
                    alive_workers.add(w.decode("utf-8") if isinstance(w, bytes) else w)

            dead_checkpoints = await self.distributed_store.list_dead_worker_checkpoints(
                list(alive_workers)
            )

            for run_id, dead_worker_id in dead_checkpoints:
                logger.warning(
                    "Found checkpoint %s owned by dead worker %s",
                    run_id,
                    dead_worker_id,
                )
                success = await self.distributed_store.take_ownership(run_id, self.worker_id)
                if success:
                    logger.info(
                        "Took ownership of checkpoint %s from dead worker %s",
                        run_id,
                        dead_worker_id,
                    )
                else:
                    logger.warning("Failed to take ownership of checkpoint %s", run_id)
        except Exception as exc:
            logger.error("Error handling stale checkpoints: %s", exc)
