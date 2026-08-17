"""Routes stage execution to either the local actor scheduler or the distributed job queue."""

import asyncio
import json
import logging
import time
from typing import Any, cast

from src.core.contracts.task_envelope import TaskEnvelope

logger = logging.getLogger(__name__)


class StageDispatcher:
    """Routes stage execution to either the local actor scheduler or
    the distributed job queue.

    When a ``JobQueue`` is provided, eligible stages are enqueued as
    ``TaskEnvelope`` jobs so that remote workers can pick them up.
    Stages that cannot be distributed (e.g. checkpoint-sensitive) are
    always executed locally via the actor scheduler.
    """

    _LOCAL_ONLY_STAGES: frozenset[str] = frozenset(
        {
            "reporting",
            "sarif_export",
            "report_distribution",
        }
    )

    def __init__(self, queue: Any | None = None) -> None:
        self._queue = queue
        self._pending_job_ids: dict[str, str] = {}

    @property
    def has_queue(self) -> bool:
        return self._queue is not None

    def set_queue(self, queue: Any) -> None:
        self._queue = queue
        if queue is not None:
            try:
                from src.infrastructure.observability.system_sampler import get_system_sampler

                get_system_sampler()._queue = queue
            except Exception:
                logger.warning("Operation failed in stage_dispatcher.py", exc_info=True)

    async def enqueue_stage(
        self,
        stage_name: str,
        ctx: Any,
        config: Any,
        *,
        priority: int = 5,
    ) -> str | None:
        if self._queue is None:
            return None
        if stage_name in self._LOCAL_ONLY_STAGES:
            return None

        envelope = TaskEnvelope(
            type=stage_name,
            payload={
                "target_name": str(getattr(config, "target_name", "")),
                "run_id": str(getattr(ctx, "run_id", "")),
                "scope_entries": list(getattr(ctx, "scope_entries", []) or []),
            },
            metadata={
                "source": "orchestrator",
                "pipeline_run_id": str(getattr(ctx, "run_id", "")),
            },
        )
        try:
            job_id = await self._queue.enqueue(envelope, priority=priority)
            self._pending_job_ids[stage_name] = job_id
            logger.info("Enqueued stage '%s' as job %s", stage_name, job_id)
            return str(job_id)
        except Exception as exc:
            logger.warning(
                "Failed to enqueue stage '%s', will execute locally: %s",
                stage_name,
                exc,
            )
            return None

    async def enqueue_stages(
        self,
        stage_names: list[str],
        ctx: Any,
        config: Any,
        *,
        priority: int = 5,
    ) -> dict[str, str]:
        result: dict[str, str] = {}
        for name in stage_names:
            job_id = await self.enqueue_stage(name, ctx, config, priority=priority)
            if job_id is not None:
                result[name] = job_id
        return result

    async def await_job_result(
        self, stage_name: str, *, timeout: float = 600.0
    ) -> dict[str, Any] | None:
        if self._queue is None:
            return None
        job_id = self._pending_job_ids.get(stage_name)
        if job_id is None:
            return None

        deadline = time.time() + timeout
        job_key = f"queue:{self._queue.queue_name}:job:{job_id}"

        while time.time() < deadline:
            job_data = await asyncio.to_thread(
                self._queue.redis.execute_command, "HGETALL", job_key
            )
            if not job_data:
                await asyncio.sleep(1.0)
                continue

            def _decode(v: bytes | str) -> str:
                return v.decode("utf-8") if isinstance(v, bytes) else str(v)

            state = _decode(job_data.get(b"state", b""))
            if state == "completed":
                result_raw = _decode(job_data.get(b"result", b"{}"))
                try:
                    return cast(dict[str, Any], json.loads(result_raw))
                except (json.JSONDecodeError, TypeError):
                    return {"status": "ok"}
            elif state in ("dead_letter", "cancelled"):
                error = _decode(job_data.get(b"error", b"unknown"))
                logger.warning(
                    "Stage '%s' job %s ended in %s: %s", stage_name, job_id, state, error
                )
                return {"status": "failed", "error": error}

            await asyncio.sleep(1.0)

        logger.warning("Timeout waiting for stage '%s' job %s", stage_name, job_id)
        return None

    def clear_completed(self, stage_name: str) -> None:
        self._pending_job_ids.pop(stage_name, None)
