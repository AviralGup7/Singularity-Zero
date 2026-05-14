"""Unit tests for the distributed job queue module."""

import time
import unittest
from unittest.mock import MagicMock

import pytest

from src.infrastructure.queue.job_queue import JobQueue, RetryPolicy
from src.infrastructure.queue.models import Job, JobState, WorkerInfo


class QueueTestBase(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.mock_redis_client = MagicMock()
        self.mock_redis_client.execute_command = MagicMock(return_value=None)
        self.mock_redis_client.pipeline = MagicMock()
        mock_pipe = MagicMock()
        mock_pipe.execute = MagicMock(return_value=[])
        self.mock_redis_client.pipeline.return_value.__enter__ = MagicMock(return_value=mock_pipe)
        self.mock_redis_client.pipeline.return_value.__exit__ = MagicMock(return_value=False)


@pytest.mark.unit
class TestJobState(unittest.TestCase):
    def test_job_state_values(self) -> None:
        assert JobState.PENDING.value == "pending"
        assert JobState.CLAIMED.value == "claimed"
        assert JobState.RUNNING.value == "running"
        assert JobState.COMPLETED.value == "completed"
        assert JobState.FAILED.value == "failed"
        assert JobState.RETRYING.value == "retrying"
        assert JobState.DEAD_LETTER.value == "dead_letter"
        assert JobState.CANCELLED.value == "cancelled"


@pytest.mark.unit
class TestJob(unittest.TestCase):
    def test_job_defaults(self) -> None:
        job = Job(id="j1", type="scan")
        assert job.id == "j1"
        assert job.type == "scan"
        assert job.payload == {}
        assert job.priority == 5
        assert job.state == JobState.PENDING
        assert job.retries == 0
        assert job.max_retries == 3
        assert job.error is None
        assert job.worker_id is None
        assert job.result is None
        assert job.metadata == {}
        assert job.queue_name == "default"

    def test_job_auto_id(self) -> None:
        job = Job(type="scan")
        assert job.id is not None
        assert len(job.id) > 0

    def test_job_mark_claimed(self) -> None:
        job = Job(id="j1", type="scan")
        job.mark_claimed("w1", 300.0)
        assert job.state == JobState.CLAIMED
        assert job.worker_id == "w1"
        assert job.lease_expires_at is not None

    def test_job_mark_running(self) -> None:
        job = Job(id="j1", type="scan")
        job.mark_claimed("w1", 300.0)
        job.mark_running()
        assert job.state == JobState.RUNNING
        assert job.started_at is not None

    def test_job_mark_completed(self) -> None:
        job = Job(id="j1", type="scan")
        job.mark_completed({"result": "ok"})
        assert job.state == JobState.COMPLETED
        assert job.completed_at is not None
        assert job.result == {"result": "ok"}
        assert job.lease_expires_at is None

    def test_job_mark_failed(self) -> None:
        job = Job(id="j1", type="scan")
        job.mark_failed("connection error")
        assert job.state == JobState.FAILED
        assert job.error == "connection error"
        assert job.lease_expires_at is None

    def test_job_mark_retrying(self) -> None:
        job = Job(id="j1", type="scan")
        job.mark_claimed("w1", 300.0)
        job.mark_failed("error")
        job.mark_retrying()
        assert job.state == JobState.RETRYING
        assert job.retries == 1
        assert job.worker_id is None

    def test_job_mark_dead_letter(self) -> None:
        job = Job(id="j1", type="scan")
        job.mark_dead_letter()
        assert job.state == JobState.DEAD_LETTER
        assert job.completed_at is not None
        assert job.worker_id is None

    def test_job_mark_cancelled(self) -> None:
        job = Job(id="j1", type="scan")
        job.mark_cancelled()
        assert job.state == JobState.CANCELLED
        assert job.completed_at is not None

    def test_job_can_retry(self) -> None:
        job = Job(id="j1", type="scan", retries=0, max_retries=3)
        assert job.can_retry() is True

    def test_job_can_retry_exhausted(self) -> None:
        job = Job(id="j1", type="scan", retries=3, max_retries=3)
        assert job.can_retry() is False

    def test_job_can_retry_cancelled(self) -> None:
        job = Job(id="j1", type="scan", state=JobState.CANCELLED)
        assert job.can_retry() is False

    def test_job_is_lease_expired(self) -> None:
        job = Job(id="j1", type="scan")
        assert job.is_lease_expired() is False

    def test_job_is_lease_expired_set(self) -> None:
        job = Job(id="j1", type="scan")
        job.lease_expires_at = time.time() - 10
        assert job.is_lease_expired() is True

    def test_job_to_redis_hash(self) -> None:
        job = Job(id="j1", type="scan", payload={"key": "val"}, priority=7)
        h = job.to_redis_hash()
        assert h["id"] == "j1"
        assert h["type"] == "scan"
        assert h["priority"] == "7"
        assert h["state"] == "pending"

    def test_job_from_redis_hash(self) -> None:
        job = Job(id="j1", type="scan", payload={"key": "val"}, priority=7)
        h = job.to_redis_hash()
        restored = Job.from_redis_hash(h)
        assert restored.id == "j1"
        assert restored.type == "scan"
        assert restored.priority == 7
        assert restored.payload == {"key": "val"}


@pytest.mark.unit
class TestWorkerInfo(unittest.TestCase):
    def test_worker_info_defaults(self) -> None:
        info = WorkerInfo(id="w1")
        assert info.id == "w1"
        assert info.hostname == "unknown"
        assert info.pid == 0
        assert info.status == "idle"
        assert info.concurrency == 1
        assert info.active_jobs == []
        assert info.total_processed == 0
        assert info.total_failed == 0

    def test_worker_info_is_alive(self) -> None:
        info = WorkerInfo(id="w1")
        assert info.is_alive() is True

    def test_worker_info_is_dead(self) -> None:
        info = WorkerInfo(id="w1")
        info.last_heartbeat = time.time() - 60
        assert info.is_alive(timeout_seconds=30.0) is False

    def test_worker_info_to_redis_hash(self) -> None:
        info = WorkerInfo(id="w1", status="busy", concurrency=4)
        h = info.to_redis_hash()
        assert h["id"] == "w1"
        assert h["status"] == "busy"
        assert h["concurrency"] == "4"

    def test_worker_info_from_redis_hash(self) -> None:
        info = WorkerInfo(id="w1", status="busy", active_jobs=["j1", "j2"])
        h = info.to_redis_hash()
        restored = WorkerInfo.from_redis_hash(h)
        assert restored.id == "w1"
        assert restored.status == "busy"
        assert restored.active_jobs == ["j1", "j2"]


@pytest.mark.unit
class TestRetryPolicy(unittest.TestCase):
    def test_default_policy(self) -> None:
        policy = RetryPolicy(jitter=False)
        assert policy.max_retries == 3
        assert policy.backoff_multiplier == 2.0
        assert policy.initial_delay == 1.0
        assert policy.max_delay == 300.0

    def test_get_delay_exponential(self) -> None:
        policy = RetryPolicy(jitter=False, initial_delay=1.0, backoff_multiplier=2.0)
        assert policy.get_delay(0) == 1.0
        assert policy.get_delay(1) == 2.0
        assert policy.get_delay(2) == 4.0

    def test_get_delay_capped(self) -> None:
        policy = RetryPolicy(jitter=False, initial_delay=100.0, max_delay=200.0)
        delay = policy.get_delay(3)
        assert delay <= 200.0

    def test_custom_policy(self) -> None:
        policy = RetryPolicy(max_retries=5, initial_delay=2.0, backoff_multiplier=3.0, jitter=False)
        assert policy.max_retries == 5
        assert policy.get_delay(0) == 2.0
        assert policy.get_delay(1) == 6.0


@pytest.mark.unit
class TestJobQueue(QueueTestBase):
    def test_queue_init(self) -> None:
        queue = JobQueue(redis_client=self.mock_redis_client, queue_name="test")
        assert queue.queue_name == "test"
        assert queue.lease_seconds == 300.0

    def test_queue_register_handler(self) -> None:
        queue = JobQueue(redis_client=self.mock_redis_client)

        def handler(job):  # noqa: ANN001
            return {"ok": True}

        queue.register_handler("scan", handler)
        assert queue.get_handler("scan") is handler
        assert queue.get_handler("unknown") is None

    def test_queue_key_namespacing(self) -> None:
        queue = JobQueue(redis_client=self.mock_redis_client, queue_name="myqueue")
        assert queue._key("queue") == "queue:myqueue:queue"
        assert queue._job_key("j1") == "queue:myqueue:job:j1"

    @pytest.mark.asyncio
    async def test_enqueue_uses_fallback(self) -> None:
        queue = JobQueue(redis_client=self.mock_redis_client, queue_name="test")
        from src.core.contracts.task_envelope import TaskEnvelope

        task = TaskEnvelope(type="scan", payload={"target": "example.com"})
        job_id = await queue.enqueue(task, priority=5)
        assert job_id is not None
        assert len(job_id) > 0

    @pytest.mark.asyncio
    async def test_get_job_not_found(self) -> None:
        queue = JobQueue(redis_client=self.mock_redis_client)
        self.mock_redis_client.execute_command.return_value = None
        result = await queue.get_job("nonexistent")
        assert result is None

    @pytest.mark.asyncio
    async def test_get_queue_length(self) -> None:
        queue = JobQueue(redis_client=self.mock_redis_client)
        self.mock_redis_client.execute_command.return_value = 5
        length = await queue.get_queue_length()
        assert length == 5

    @pytest.mark.asyncio
    async def test_get_dead_letter_count(self) -> None:
        queue = JobQueue(redis_client=self.mock_redis_client)
        self.mock_redis_client.execute_command.return_value = 3
        count = await queue.get_dead_letter_count()
        assert count == 3

    @pytest.mark.asyncio
    async def test_get_metrics(self) -> None:
        queue = JobQueue(redis_client=self.mock_redis_client)
        self.mock_redis_client.execute_command.return_value = {}
        metrics = await queue.get_metrics()
        assert "queue_length" in metrics
        assert "dead_letter_count" in metrics
        assert "queue_name" in metrics

    @pytest.mark.asyncio
    async def test_cancel_job_not_found(self) -> None:
        queue = JobQueue(redis_client=self.mock_redis_client)
        self.mock_redis_client.execute_command.return_value = None
        result = await queue.cancel_job("nonexistent")
        assert result is False

    @pytest.mark.asyncio
    async def test_cancel_completed_job(self) -> None:
        queue = JobQueue(redis_client=self.mock_redis_client)
        job = Job(id="j1", type="scan", state=JobState.COMPLETED)
        self.mock_redis_client.execute_command.return_value = job.to_redis_hash()
        result = await queue.cancel_job("j1")
        assert result is False

    @pytest.mark.asyncio
    async def test_list_dead_letters_empty(self) -> None:
        queue = JobQueue(redis_client=self.mock_redis_client)
        self.mock_redis_client.execute_command.return_value = []
        dead_letters = await queue.list_dead_letters()
        assert dead_letters == []
