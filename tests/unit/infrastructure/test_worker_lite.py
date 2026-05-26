"""Unit tests for the ultra-lightweight standalone sub-node worker."""

import asyncio
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.infrastructure.queue.worker_lite import LiteWorker, setup_tools


@pytest.mark.unit
class TestLiteWorker(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.worker_id = "test-lite-worker"
        self.redis_url = "redis://localhost:6379/0"
        self.queue_name = "security-pipeline"
        
        # Mock Redis client with AsyncMock methods
        self.mock_redis = AsyncMock()
        self.mock_redis.ping = AsyncMock(return_value=True)
        self.mock_redis.script_load = AsyncMock(side_effect=lambda script: f"sha_{hash(script)}")
        self.mock_redis.hset = AsyncMock(return_value=1)
        self.mock_redis.sadd = AsyncMock(return_value=1)
        self.mock_redis.delete = AsyncMock(return_value=1)
        self.mock_redis.expire = AsyncMock(return_value=True)
        self.mock_redis.hget = AsyncMock(return_value=None)
        self.mock_redis.hgetall = AsyncMock(return_value={})
        self.mock_redis.zrevrange = AsyncMock(return_value=[])
        self.mock_redis.evalsha = AsyncMock(return_value=[1, "claimed"])
        self.mock_redis.srem = AsyncMock(return_value=1)
        self.mock_redis.aclose = AsyncMock()
        
        # Patch redis.asyncio.from_url to return our mock
        self.redis_patcher = patch("redis.asyncio.from_url", return_value=self.mock_redis)
        self.redis_patcher.start()

    def tearDown(self) -> None:
        self.redis_patcher.stop()

    def test_worker_init(self) -> None:
        worker = LiteWorker(
            worker_id=self.worker_id,
            redis_url=self.redis_url,
            queue_name=self.queue_name,
            concurrency=2,
        )
        assert worker.worker_id == self.worker_id
        assert worker.redis_url == self.redis_url
        assert worker.queue_name == self.queue_name
        assert worker.concurrency == 2
        assert "recon" in worker.capabilities
        assert "lite" in worker.capabilities

    @pytest.mark.asyncio
    async def test_worker_registration(self) -> None:
        worker = LiteWorker(
            worker_id=self.worker_id,
            redis_url=self.redis_url,
            queue_name=self.queue_name,
        )
        worker._redis = self.mock_redis
        await worker._register()
        
        # Verify worker info and capabilities were written to Redis
        assert self.mock_redis.hset.call_count >= 1
        assert self.mock_redis.sadd.call_count >= 2
        assert self.mock_redis.delete.call_count >= 1

    @pytest.mark.asyncio
    async def test_worker_heartbeat(self) -> None:
        worker = LiteWorker(
            worker_id=self.worker_id,
            redis_url=self.redis_url,
            queue_name=self.queue_name,
            heartbeat_interval=0.01,
        )
        worker._redis = self.mock_redis
        worker._running = True
        
        # Let heartbeat run for a split second and check
        task = asyncio.create_task(worker._heartbeat())
        await asyncio.sleep(0.03)
        worker._running = False
        task.cancel()
        
        assert self.mock_redis.hset.call_count >= 1

    @pytest.mark.asyncio
    @patch("asyncio.create_subprocess_exec")
    async def test_execute_recon_command(self, mock_subprocess: MagicMock) -> None:
        # Mock asyncio subprocess capture
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"sub1.example.com\nsub2.example.com\n", b""))
        mock_subprocess.return_value = mock_process

        worker = LiteWorker(
            worker_id=self.worker_id,
            redis_url=self.redis_url,
        )
        
        results = await worker._execute_recon_command(["subfinder", "-d", "example.com"])
        assert results == ["sub1.example.com", "sub2.example.com"]
        mock_subprocess.assert_called_once()

    @pytest.mark.asyncio
    @patch("asyncio.create_subprocess_exec")
    async def test_process_job_subdomains(self, mock_subprocess: MagicMock) -> None:
        # Mock subfinder execution
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"target.example.com\n", b""))
        mock_subprocess.return_value = mock_process

        worker = LiteWorker(
            worker_id=self.worker_id,
            redis_url=self.redis_url,
        )
        worker._redis = self.mock_redis
        worker._shas = {"complete_job": "complete_sha", "fail_job": "fail_sha"}
        
        payload = {"payload": {"target": "example.com"}}
        await worker._process_job("job_123", "subdomains", payload)
        
        # Verify job state updates and completion evalsha call
        assert self.mock_redis.hset.called
        assert self.mock_redis.evalsha.called
        # Check that we called completed_job SHA
        self.mock_redis.evalsha.assert_any_call(
            "complete_sha",
            3,
            "queue:security-pipeline:job:job_123",
            "queue:security-pipeline:worker:test-lite-worker:jobs",
            "queue:security-pipeline:metrics",
            unittest.mock.ANY,
            unittest.mock.ANY,
        )

    @pytest.mark.asyncio
    @patch("asyncio.create_subprocess_exec")
    async def test_process_job_failure(self, mock_subprocess: MagicMock) -> None:
        # Mock failing subprocess execution
        mock_process = AsyncMock()
        mock_process.returncode = 1
        mock_process.communicate = AsyncMock(return_value=(b"", b"permission denied"))
        mock_subprocess.return_value = mock_process

        worker = LiteWorker(
            worker_id=self.worker_id,
            redis_url=self.redis_url,
        )
        worker._redis = self.mock_redis
        worker._shas = {"complete_job": "complete_sha", "fail_job": "fail_sha"}
        
        # Mock retry policy parameters returned from job hash
        self.mock_redis.hget.side_effect = lambda key, field: "0" if field == "retries" else "3"

        payload = {"payload": {"target": "example.com"}}
        await worker._process_job("job_123", "subdomains", payload)
        
        # Check that we called fail_job SHA
        self.mock_redis.evalsha.assert_any_call(
            "fail_sha",
            5,
            "queue:security-pipeline:job:job_123",
            "queue:security-pipeline:worker:test-lite-worker:jobs",
            "queue:security-pipeline:queue",
            "queue:security-pipeline:dead_letter",
            "queue:security-pipeline:metrics",
            unittest.mock.ANY,
            "0",
            "3",
            unittest.mock.ANY,
            "1.0",
            "2.0",
            "300.0",
        )

    @pytest.mark.asyncio
    async def test_poll_and_process_empty_queue(self) -> None:
        worker = LiteWorker(
            worker_id=self.worker_id,
            redis_url=self.redis_url,
            poll_interval=0.01,
        )
        worker._redis = self.mock_redis
        worker._running = True
        
        self.mock_redis.zrevrange = AsyncMock(return_value=[])
        
        task = asyncio.create_task(worker._poll_and_process())
        await asyncio.sleep(0.02)
        worker._running = False
        task.cancel()
        
        self.mock_redis.zrevrange.assert_called_with("queue:security-pipeline:queue", 0, 5)

    @pytest.mark.asyncio
    async def test_poll_and_process_claims_job(self) -> None:
        worker = LiteWorker(
            worker_id=self.worker_id,
            redis_url=self.redis_url,
            poll_interval=0.01,
        )
        worker._redis = self.mock_redis
        worker._running = True
        worker._shas = {"claim_job": "claim_sha"}
        
        # Queue returns one candidate job
        self.mock_redis.zrevrange = AsyncMock(return_value=[b"queue:security-pipeline:job:job_abc"])
        # Claim succeeds
        self.mock_redis.evalsha = AsyncMock(return_value=[1, "claimed"])
        # Fetching details returns valid job
        self.mock_redis.hgetall = AsyncMock(return_value={
            b"type": b"subdomains",
            b"payload": b"{\"payload\": {\"target\": \"example.com\"}}",
        })
        
        # Patch _process_job to not actually spawn a subprocess
        with patch.object(worker, "_process_job", new_callable=AsyncMock) as mock_process_job:
            task = asyncio.create_task(worker._poll_and_process())
            await asyncio.sleep(0.03)
            worker._running = False
            task.cancel()
            
            mock_process_job.assert_called_with("job_abc", "subdomains", {"payload": {"target": "example.com"}})

    @pytest.mark.asyncio
    async def test_cleanup(self) -> None:
        worker = LiteWorker(
            worker_id=self.worker_id,
            redis_url=self.redis_url,
        )
        worker._redis = self.mock_redis
        worker._shas = {"release_lease": "release_sha"}
        
        # Mock active tasks
        task_mock = MagicMock()
        task_mock.get_name = MagicMock(return_value="job_999")
        worker._active_tasks.add(task_mock)
        
        await worker._cleanup()
        
        # Verify active task lease was released
        self.mock_redis.evalsha.assert_called_with(
            "release_sha",
            3,
            "queue:security-pipeline:job:job_999",
            "queue:security-pipeline:worker:test-lite-worker:jobs",
            "queue:security-pipeline:queue",
        )
        
        # Verify worker is deleted
        self.mock_redis.delete.assert_called_with("queue:security-pipeline:worker:test-lite-worker")
        self.mock_redis.srem.assert_called_with("queue:security-pipeline:workers", self.worker_id)


@pytest.mark.unit
class TestSetupTools(unittest.TestCase):
    @patch("pathlib.Path.exists", return_value=True)
    @patch("builtins.open", new_callable=unittest.mock.mock_open)
    @patch("urllib.request.urlopen")
    @patch("urllib.request.Request")
    @patch("zipfile.is_zipfile", return_value=True)
    @patch("zipfile.ZipFile")
    @patch("os.chmod")
    @patch("pathlib.Path.mkdir")
    @patch("shutil.copyfileobj")
    def test_setup_tools_success(
        self,
        mock_copy,
        mock_mkdir,
        mock_chmod,
        mock_zipfile,
        mock_is_zipfile,
        mock_request,
        mock_urlopen,
        mock_file_open,
        mock_exists,
    ) -> None:
        # Mock temporary zip archive contents
        mock_zip_instance = MagicMock()
        mock_zip_instance.namelist = MagicMock(return_value=[
            "subfinder", "httpx", "katana",
            "subfinder.exe", "httpx.exe", "katana.exe"
        ])
        mock_zipfile.return_value.__enter__.return_value = mock_zip_instance

        # Run tool setup
        setup_tools(dest_dir="/tmp/bin")

        # Verify that setup downloads all three tools
        assert mock_urlopen.call_count == 3
        assert mock_copy.call_count >= 3
        if sys.platform != "win32":
            assert mock_chmod.call_count == 3
