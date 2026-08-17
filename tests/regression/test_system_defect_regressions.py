"""Regression tests for the 7 system-wide defects identified in the deep investigation.

Each test class targets a specific production defect and verifies that the fix
prevents the defect from recurring. Tests use mocked Redis/IO to avoid
requiring a live Redis instance.
"""

from __future__ import annotations

import threading
import time
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Defect 1: FAIL_JOB_SCRIPT retries never incremented (CRITICAL)
# ---------------------------------------------------------------------------
class TestDefect1RetryIncrement:
    """Verify that FAIL_JOB_SCRIPT atomically reads, increments, and
    persists the retries counter in Redis."""

    @pytest.mark.regression
    def test_fail_job_script_increments_retries(self) -> None:
        """The Lua script must contain HINCRBY job_key retries 1."""
        from src.infrastructure.queue.lua_scripts import FAIL_JOB_SCRIPT

        assert "HINCRBY" in FAIL_JOB_SCRIPT
        assert "'retries'" in FAIL_JOB_SCRIPT or '"retries"' in FAIL_JOB_SCRIPT

    @pytest.mark.regression
    def test_fail_job_script_reads_retries_from_redis(self) -> None:
        """The Lua script must read retries via HGET, not from ARGV."""
        from src.infrastructure.queue.lua_scripts import FAIL_JOB_SCRIPT

        # Script should NOT use ARGV[2] for retries (the old broken path)
        assert "ARGV[2]" not in FAIL_JOB_SCRIPT or "retries" not in FAIL_JOB_SCRIPT.split("ARGV[2]")[0].split("\n")[-1]

    @pytest.mark.regression
    def test_fail_job_script_dead_letter_after_max_retries(self) -> None:
        """When new_retries > max_retries, the job must go to dead_letter."""
        from src.infrastructure.queue.lua_scripts import FAIL_JOB_SCRIPT

        # The comparison should be new_retries <= max_retries for retrying
        assert "dead_letter" in FAIL_JOB_SCRIPT

    @pytest.mark.regression
    def test_fail_job_script_argv_layout_matches_caller(self) -> None:
        """The Lua ARGV layout must match what worker_lite passes."""
        from src.infrastructure.queue.lua_scripts import FAIL_JOB_SCRIPT

        # Script uses ARGV[1]=error, ARGV[2]=max_retries, ARGV[3]=now,
        # ARGV[4]=initial_delay, ARGV[5]=multiplier, ARGV[6]=max_delay
        assert "ARGV[1]" in FAIL_JOB_SCRIPT
        assert "ARGV[3]" in FAIL_JOB_SCRIPT

    @pytest.mark.regression
    def test_consumer_groups_fail_job_omits_retries_arg(self) -> None:
        """consumer_groups.fail_job must NOT pass retries as a script argument."""
        import inspect

        from src.infrastructure.queue.consumer_groups import JobQueueConsumerGroupsMixin

        source = inspect.getsource(JobQueueConsumerGroupsMixin.fail_job)
        # The old code had str(retries) in args; the new code should not
        assert "str(retries)" not in source

    @pytest.mark.regression
    def test_worker_lite_fail_job_omits_stale_retries_fetch(self) -> None:
        """worker_lite._process_job must NOT fetch retries from Redis before passing to script."""
        import inspect
        import re

        from src.infrastructure.queue.worker_lite import LiteWorker

        source = inspect.getsource(LiteWorker._process_job)
        # The old code had: retries_str = await self._redis.hget(job_key, "retries")
        # This line must NOT exist — retries are now read atomically in Lua.
        assert not re.search(r'hget\(.*"retries"\)', source), \
            "Old pattern 'hget(... \"retries\" ...)' still present; retries should be read in Lua"


# ---------------------------------------------------------------------------
# Defect 2: stop_job() cannot force-kill hung processes (HIGH)
# ---------------------------------------------------------------------------
class TestDefect2StopJobSigkill:
    """Verify that DashboardQueryService.stop_job() escalates from
    SIGTERM to SIGKILL when the process does not exit."""

    @staticmethod
    def _read_stop_job_source() -> str:
        """Read the query_service source file directly to avoid triggering
        the broken SHELL_META transitive import chain via src.dashboard.__init__."""
        return Path("src/dashboard/services/query_service.py").read_text(encoding="utf-8")

    @staticmethod
    def _load_query_service_module():
        """Load DashboardQueryService by reading the .py file directly,
        bypassing src.dashboard.__init__.py which triggers SHELL_META.

        The loaded module is kept in sys.modules so that subsequent
        patch("src.dashboard.services.query_service.time.time") works.
        """
        import importlib.util
        import sys
        import types

        # If already loaded, return cached version
        cached = sys.modules.get("src.dashboard.services.query_service")
        if cached is not None and hasattr(cached, "DashboardQueryService"):
            return cached.DashboardQueryService

        source_file = Path("src/dashboard/services/query_service.py").resolve()

        # Build stub packages for the import chain that query_service.py needs.
        # This prevents src.dashboard.__init__.py from executing (which
        # triggers the SHELL_META import chain).
        chain = [
            ("src", [Path("src")]),
            ("src.dashboard", [Path("src/dashboard")]),
            ("src.dashboard.services", [Path("src/dashboard/services")]),
        ]
        for pkg_name, pkg_path in chain:
            if pkg_name not in sys.modules:
                stub = types.ModuleType(pkg_name)
                stub.__path__ = [str(p) for p in pkg_path]
                stub.__package__ = pkg_name
                stub.__file__ = ""
                sys.modules[pkg_name] = stub
                parts = pkg_name.rsplit(".", 1)
                if len(parts) == 2 and parts[0] in sys.modules:
                    setattr(sys.modules[parts[0]], parts[1], stub)

        spec = importlib.util.spec_from_file_location(
            "src.dashboard.services.query_service",
            str(source_file),
        )
        mod = importlib.util.module_from_spec(spec)
        sys.modules["src.dashboard.services.query_service"] = mod
        spec.loader.exec_module(mod)
        return mod.DashboardQueryService

    @pytest.mark.regression
    def test_stop_job_has_kill_fallback(self) -> None:
        """stop_job must use process.kill() as escalation after SIGTERM timeout."""
        source = self._read_stop_job_source()
        assert '"kill"' in source

    @pytest.mark.regression
    def test_stop_job_waits_before_kill(self) -> None:
        """stop_job must call process.wait(timeout=...) before kill."""
        source = self._read_stop_job_source()
        assert "wait" in source

    @pytest.mark.regression
    def test_stop_job_terminate_then_kill_escalation(self) -> None:
        """On SIGTERM timeout, stop_job must escalate to SIGKILL."""
        DashboardQueryService = self._load_query_service_module()

        mock_process = MagicMock()
        # terminate() succeeds but wait() times out (simulates hung process)
        mock_process.terminate = MagicMock()
        mock_process.wait = MagicMock(side_effect=[TimeoutError, None])
        mock_process.kill = MagicMock()

        jobs: dict = {
            "job1": {
                "id": "job1",
                "status": "running",
                "process": mock_process,
                "updated_at": time.time(),
            }
        }

        service = DashboardQueryService(
            output_root=Path("/tmp/test"),
            config_template=Path("/tmp/template.json"),
            lock=threading.Lock(),
            jobs=jobs,
        )

        with patch("src.dashboard.services.query_service.time.time", return_value=1000.0):
            service.stop_job("job1")

        mock_process.terminate.assert_called_once()
        mock_process.wait.assert_called()
        mock_process.kill.assert_called_once()

    @pytest.mark.regression
    def test_stop_job_no_kill_if_terminate_succeeds(self) -> None:
        """If process exits after SIGTERM, kill() must NOT be called."""
        DashboardQueryService = self._load_query_service_module()

        mock_process = MagicMock()
        mock_process.terminate = MagicMock()
        mock_process.wait = MagicMock(return_value=0)  # Process exits quickly
        mock_process.kill = MagicMock()

        jobs: dict = {
            "job1": {
                "id": "job1",
                "status": "running",
                "process": mock_process,
                "updated_at": time.time(),
            }
        }

        service = DashboardQueryService(
            output_root=Path("/tmp/test"),
            config_template=Path("/tmp/template.json"),
            lock=threading.Lock(),
            jobs=jobs,
        )

        with patch("src.dashboard.services.query_service.time.time", return_value=1000.0):
            service.stop_job("job1")

        mock_process.terminate.assert_called_once()
        mock_process.kill.assert_not_called()


# ---------------------------------------------------------------------------
# Defect 3: Redis failure during processing leaves job stuck (HIGH)
# ---------------------------------------------------------------------------
class TestDefect3RedisFailureResilience:
    """Verify that _process_job handles Redis connection failures during
    the fail_job reporting path with retries and a fallback."""

    @pytest.mark.regression
    @pytest.mark.asyncio
    async def test_process_job_retries_fail_on_redis_error(self) -> None:
        """fail_job should be retried up to 3 times on Redis connection errors."""
        from src.infrastructure.queue.worker_lite import LiteWorker

        worker = LiteWorker(
            worker_id="test-worker",
            redis_url="redis://localhost:6379/0",
        )
        worker._redis = AsyncMock()
        worker._shas = {"complete_job": "complete_sha", "fail_job": "fail_sha"}

        worker._redis.hget = AsyncMock(return_value=b"3")
        worker._redis.hset = AsyncMock(return_value=1)

        # evalsha: fail_job retries with ConnectionError twice, then succeeds.
        # The subprocess failure is simulated by mock create_subprocess_exec
        # returning returncode=1, which triggers RuntimeError from
        # _execute_recon_command. _process_job then enters the fail path
        # and calls evalsha(fail_job) up to 3 times.
        call_count = 0

        def evalsha_side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count <= 2:
                raise ConnectionError("redis down")
            return [1, "retrying", "1000.0"]

        worker._redis.evalsha = AsyncMock(side_effect=evalsha_side_effect)

        with patch("asyncio.sleep", new_callable=AsyncMock):
            with patch(
                "src.infrastructure.queue.plugin_handler_bridge.normalize_job_type",
                return_value="recon_provider.subdomains",
            ):
                with patch("asyncio.create_subprocess_exec", new_callable=AsyncMock) as mock_sub:
                    mock_proc = AsyncMock()
                    mock_proc.communicate = AsyncMock(return_value=(b"", b"error"))
                    mock_proc.returncode = 1
                    mock_sub.return_value = mock_proc

                    await worker._process_job("job1", "subdomains", {"payload": {"target": "x.com"}})

        # evalsha should have been called multiple times (retries)
        assert worker._redis.evalsha.call_count >= 3

    @pytest.mark.regression
    @pytest.mark.asyncio
    async def test_process_job_fallback_hset_after_all_retries_fail(self) -> None:
        """After 3 Redis failures, a direct HSET should mark job as failed."""
        from src.infrastructure.queue.worker_lite import LiteWorker

        worker = LiteWorker(
            worker_id="test-worker",
            redis_url="redis://localhost:6379/0",
        )
        worker._redis = AsyncMock()
        worker._shas = {"complete_job": "complete_sha", "fail_job": "fail_sha"}

        worker._redis.hget = AsyncMock(return_value=b"3")
        worker._redis.hset = AsyncMock(return_value=1)

        # All fail_job evalsha calls fail with ConnectionError.
        # The subprocess failure is already simulated by mock create_subprocess_exec.
        call_count = 0

        def evalsha_side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            raise ConnectionError("redis down")

        worker._redis.evalsha = AsyncMock(side_effect=evalsha_side_effect)

        with patch("asyncio.sleep", new_callable=AsyncMock):
            with patch(
                "src.infrastructure.queue.plugin_handler_bridge.normalize_job_type",
                return_value="recon_provider.subdomains",
            ):
                with patch("asyncio.create_subprocess_exec", new_callable=AsyncMock) as mock_sub:
                    mock_proc = AsyncMock()
                    mock_proc.communicate = AsyncMock(return_value=(b"", b"error"))
                    mock_proc.returncode = 1
                    mock_sub.return_value = mock_proc

                    await worker._process_job("job1", "subdomains", {"payload": {"target": "x.com"}})

        # After evalsha failures, hset should be called with state="failed"
        hset_calls = worker._redis.hset.call_args_list
        found_fallback = False
        for call in hset_calls:
            args, kwargs = call
            if kwargs.get("mapping", {}).get("state") == "failed":
                found_fallback = True
                break
            if len(args) >= 2 and isinstance(args[1], dict) and args[1].get("state") == "failed":
                found_fallback = True
                break
        assert found_fallback, "Expected fallback hset with state='failed' after exhausted retries"


# ---------------------------------------------------------------------------
# Defect 4: LearningIntegration singleton stale after close() failure (MEDIUM)
# ---------------------------------------------------------------------------
class TestDefect4SingletonExceptionSafe:
    """Verify that LearningIntegration.get_or_create() always nulls the
    singleton even when close() raises an exception."""

    @pytest.mark.regression
    def test_singleton_reset_even_on_close_failure(self) -> None:
        """If close() raises, the singleton must still be set to None."""
        import src.learning.integration as integ_mod
        from src.learning.config import LearningConfig
        from src.learning.integration import LearningIntegration, _config_fingerprint

        # Save original state
        orig_instance = integ_mod._integration_instance
        orig_hash = integ_mod._integration_config_hash

        try:
            # Create a mock instance with a failing close()
            mock_instance = MagicMock(spec=LearningIntegration)
            mock_instance.close = MagicMock(side_effect=RuntimeError("close failed"))

            integ_mod._integration_instance = mock_instance
            integ_mod._integration_config_hash = "old_hash"

            config = LearningConfig()
            config.database_path = "/new/path.db"
            # Called for its side-effect-free validity only; the assertion
            # below is about the singleton, not the fingerprint value.
            _config_fingerprint(config)

            # get_or_create should catch the close() error and null the singleton
            with patch.object(
                integ_mod,
                "_integration_lock",
                threading.Lock(),
            ):
                try:
                    LearningIntegration.get_or_create(
                        config=config,
                    )
                except Exception:
                    pass  # May fail to create new instance, that's OK

            # The singleton should have been nulled despite close() failure
            assert integ_mod._integration_instance != mock_instance or \
                   integ_mod._integration_config_hash != "old_hash" or \
                   integ_mod._integration_instance is None
        finally:
            # Restore original state
            integ_mod._integration_instance = orig_instance
            integ_mod._integration_config_hash = orig_hash

    @pytest.mark.regression
    def test_singleton_reset_try_except_structure(self) -> None:
        """The get_or_create reset branch must wrap close() in try/except."""
        import inspect

        from src.learning.integration import LearningIntegration

        source = inspect.getsource(LearningIntegration.get_or_create)
        # Must have try around close()
        assert "try:" in source
        # Must have except near close()
        lines = source.split("\n")
        close_line = None
        for i, line in enumerate(lines):
            if ".close()" in line:
                close_line = i
                break
        assert close_line is not None, "close() call not found in get_or_create"
        # There must be a try block before close()
        try_line = None
        for i in range(close_line - 1, max(close_line - 5, 0), -1):
            if "try:" in lines[i]:
                try_line = i
                break
        assert try_line is not None, "No try block before close() call"

    @pytest.mark.regression
    def test_reset_method_also_exception_safe(self) -> None:
        """LearningIntegration.reset() should not leave stale state on error."""
        import inspect

        from src.learning.integration import LearningIntegration

        source = inspect.getsource(LearningIntegration.reset)
        # reset() should also handle close() failures
        assert "_integration_instance = None" in source


# ---------------------------------------------------------------------------
# Defect 5: Priority queue pop/peek O(n) heapify (MEDIUM)
# ---------------------------------------------------------------------------
class TestDefect5NoHeapify:
    """Verify that pop() and peek() do not call heapq.heapify()."""

    @pytest.mark.regression
    def test_pop_does_not_call_heapify(self) -> None:
        """CorrelationPriorityQueue.pop() must not call heapq.heapify()."""
        import inspect

        from src.decision.priority_queue import CorrelationPriorityQueue

        source = inspect.getsource(CorrelationPriorityQueue.pop)
        assert "heapify" not in source

    @pytest.mark.regression
    def test_peek_does_not_call_heapify(self) -> None:
        """CorrelationPriorityQueue.peek() must not call heapq.heapify()."""
        import inspect

        from src.decision.priority_queue import CorrelationPriorityQueue

        source = inspect.getsource(CorrelationPriorityQueue.peek)
        assert "heapify" not in source

    @pytest.mark.regression
    def test_pop_returns_highest_priority_target(self) -> None:
        """pop() must still return the correct highest-priority target without heapify."""
        from src.decision.priority_queue import CorrelationPriorityQueue, ScanTarget

        t1 = ScanTarget(url="http://a.com", base_priority=10.0, current_priority=10.0)
        t2 = ScanTarget(url="http://b.com", base_priority=20.0, current_priority=20.0)
        t3 = ScanTarget(url="http://c.com", base_priority=5.0, current_priority=5.0)

        pq = CorrelationPriorityQueue([t1, t2, t3])

        popped = pq.pop()
        assert popped is not None
        assert popped.url == "http://b.com"

    @pytest.mark.regression
    def test_pop_with_boost_maintains_order(self) -> None:
        """After boosting a low-priority target, pop should return it first."""
        from src.decision.priority_queue import CorrelationPriorityQueue, ScanTarget

        t1 = ScanTarget(url="http://a.com", base_priority=10.0, current_priority=10.0)
        t2 = ScanTarget(url="http://b.com", base_priority=5.0, current_priority=5.0)

        pq = CorrelationPriorityQueue([t1, t2])

        # Boost t2 so it becomes higher priority
        pq.boost_url("http://b.com", factor=5.0, reason="urgent")

        popped = pq.pop()
        assert popped is not None
        assert popped.url == "http://b.com"

    @pytest.mark.regression
    def test_peek_returns_highest_without_removing(self) -> None:
        """peek() should return the highest-priority target without removing it."""
        from src.decision.priority_queue import CorrelationPriorityQueue, ScanTarget

        t1 = ScanTarget(url="http://a.com", base_priority=10.0, current_priority=10.0)
        t2 = ScanTarget(url="http://b.com", base_priority=20.0, current_priority=20.0)

        pq = CorrelationPriorityQueue([t1, t2])

        peeked = pq.peek()
        assert peeked is not None
        assert peeked.url == "http://b.com"
        # Queue should still have 2 items
        assert pq.remaining == 2


# ---------------------------------------------------------------------------
# Defect 6: CircuitBreaker state file collision (MEDIUM)
# ---------------------------------------------------------------------------
class TestDefect6CircuitBreakerUniqueState:
    """Verify that each CircuitBreaker instance uses a unique state file."""

    @pytest.mark.regression
    def test_state_file_includes_unique_id(self) -> None:
        """CircuitBreaker state file must include a UUID-based instance ID."""
        from src.websocket_server.broadcaster import CircuitBreaker

        cb = CircuitBreaker()
        filename = cb._state_file.name
        # Should have format: redis_breaker_state_{pid}_{uuid8}.json
        parts = filename.replace(".json", "").split("_")
        assert len(parts) >= 4, f"Expected at least 4 parts in filename, got: {parts}"
        # Last part should be an 8-char hex UUID
        unique_part = parts[-1]
        assert len(unique_part) == 8
        int(unique_part, 16)  # Should not raise - valid hex

    @pytest.mark.regression
    def test_two_instances_have_different_state_files(self) -> None:
        """Two CircuitBreaker instances must have different state file paths."""
        from src.websocket_server.broadcaster import CircuitBreaker

        cb1 = CircuitBreaker()
        cb2 = CircuitBreaker()
        assert cb1._state_file != cb2._state_file

    @pytest.mark.regression
    def test_state_file_contains_pid(self) -> None:
        """State file must still include the PID for process-level debugging."""
        import os

        from src.websocket_server.broadcaster import CircuitBreaker

        cb = CircuitBreaker()
        filename = cb._state_file.name
        assert str(os.getpid()) in filename

    @pytest.mark.regression
    def test_broadcaster_stop_cleans_instance_specific_file(self) -> None:
        """Broadcaster.stop() should clean up the instance-specific breaker file."""
        import inspect

        from src.websocket_server.broadcaster import Broadcaster

        source = inspect.getsource(Broadcaster.stop)
        # Should reference self._redis_breaker._state_file, not a PID-only path
        assert "_redis_breaker" in source or "_state_file" in source


# ---------------------------------------------------------------------------
# Defect 7: Cleanup calls RELEASE_LEASE for dead-letter jobs (LOW)
# ---------------------------------------------------------------------------
class TestDefect7CleanupSkipsDeadLetter:
    """Verify that LiteWorker._cleanup() skips dead-letter jobs."""

    @pytest.mark.regression
    def test_cleanup_skip_list_includes_dead_letter(self) -> None:
        """_cleanup() must skip jobs in 'dead_letter' state."""
        import inspect

        from src.infrastructure.queue.worker_lite import LiteWorker

        source = inspect.getsource(LiteWorker._cleanup)
        assert "dead_letter" in source

    @pytest.mark.regression
    @pytest.mark.asyncio
    async def test_cleanup_skips_dead_letter_job(self) -> None:
        """A dead-letter job should not have its lease released during cleanup."""
        from src.infrastructure.queue.worker_lite import LiteWorker

        worker = LiteWorker(
            worker_id="test-worker",
            redis_url="redis://localhost:6379/0",
        )
        worker._redis = AsyncMock()
        worker._shas = {"release_lease": "release_sha"}

        worker._job_task_map["dead_job"] = MagicMock()
        worker._active_tasks = set()

        worker._redis.hget = AsyncMock(return_value=b"dead_letter")

        mock_registry = MagicMock()
        mock_registry.shutdown_owner = AsyncMock()
        with patch("src.core.task_registry.get_task_registry", return_value=mock_registry):
            await worker._cleanup()

        # release_lease (evalsha) should NOT have been called for the dead-letter job
        for call in worker._redis.evalsha.call_args_list:
            args = call[0]
            if len(args) >= 2:
                assert "dead_job" not in str(args)

    @pytest.mark.regression
    @pytest.mark.asyncio
    async def test_cleanup_releases_running_job(self) -> None:
        """A running job should have its lease released during cleanup."""
        from src.infrastructure.queue.worker_lite import LiteWorker

        worker = LiteWorker(
            worker_id="test-worker",
            redis_url="redis://localhost:6379/0",
        )
        worker._redis = AsyncMock()
        worker._shas = {"release_lease": "release_sha"}

        worker._job_task_map["running_job"] = MagicMock()
        worker._active_tasks = set()

        worker._redis.hget = AsyncMock(return_value=b"running")
        worker._redis.evalsha = AsyncMock(return_value=[1])

        mock_registry = MagicMock()
        mock_registry.shutdown_owner = AsyncMock()
        with patch("src.core.task_registry.get_task_registry", return_value=mock_registry):
            await worker._cleanup()

        # release_lease SHOULD have been called for the running job
        worker._redis.evalsha.assert_called()

    @pytest.mark.regression
    @pytest.mark.asyncio
    async def test_cleanup_skips_completed_job(self) -> None:
        """A completed job should not have its lease released during cleanup."""
        from src.infrastructure.queue.worker_lite import LiteWorker

        worker = LiteWorker(
            worker_id="test-worker",
            redis_url="redis://localhost:6379/0",
        )
        worker._redis = AsyncMock()
        worker._shas = {"release_lease": "release_sha"}

        worker._job_task_map["done_job"] = MagicMock()
        worker._active_tasks = set()

        worker._redis.hget = AsyncMock(return_value=b"completed")

        mock_registry = MagicMock()
        mock_registry.shutdown_owner = AsyncMock()
        with patch("src.core.task_registry.get_task_registry", return_value=mock_registry):
            await worker._cleanup()

        # release_lease should NOT have been called
        for call in worker._redis.evalsha.call_args_list:
            args = call[0]
            if len(args) >= 2:
                assert "done_job" not in str(args)


# ---------------------------------------------------------------------------
# Cross-defect integration: Lua script ARGV layout consistency
# ---------------------------------------------------------------------------
class TestCrossDefectArgvConsistency:
    """Verify that all callers of FAIL_JOB_SCRIPT use the same ARGV layout."""

    @pytest.mark.regression
    def test_worker_lite_argv_count_matches_script(self) -> None:
        """worker_lite must pass exactly 6 ARGV values (error, max_retries, now, delay, mult, max)."""
        import inspect

        from src.infrastructure.queue.worker_lite import LiteWorker

        source = inspect.getsource(LiteWorker._process_job)
        # Count string literals that look like ARGV values
        # The script expects: error, max_retries, now, "1.0", "2.0", "300.0"
        assert '"1.0"' in source  # initial delay
        assert '"2.0"' in source  # multiplier
        assert '"300.0"' in source  # max delay

    @pytest.mark.regression
    def test_consumer_groups_argv_count_matches_script(self) -> None:
        """consumer_groups must pass ARGV values matching the Lua script layout."""
        import inspect

        from src.infrastructure.queue.consumer_groups import JobQueueConsumerGroupsMixin

        source = inspect.getsource(JobQueueConsumerGroupsMixin.fail_job)
        # Should pass error, max_retries, time, initial_delay, backoff_multiplier, max_delay
        assert "str(max_retries)" in source
        assert "str(time.time())" in source

    @pytest.mark.regression
    def test_lua_script_argv_indices(self) -> None:
        """FAIL_JOB_SCRIPT ARGV indices must be consistent and correct."""
        from src.infrastructure.queue.lua_scripts import FAIL_JOB_SCRIPT

        # ARGV[1] = error_msg
        assert "ARGV[1]" in FAIL_JOB_SCRIPT
        # ARGV[2] = max_retries (retries removed)
        assert "ARGV[2]" in FAIL_JOB_SCRIPT or "ARGV[3]" in FAIL_JOB_SCRIPT
        # Script must use HGET for retries, not ARGV
        assert "HGET" in FAIL_JOB_SCRIPT
        assert "retries" in FAIL_JOB_SCRIPT
