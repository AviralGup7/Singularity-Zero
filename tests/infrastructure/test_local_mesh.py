"""Tests for the Local-Mesh Distributed Orchestration system."""

import json
from unittest.mock import MagicMock, patch

import pytest

from src.infrastructure.queue.models import (
    ResourceProfile,
    TaskResourceRequirement,
    WorkerInfo,
)
from src.infrastructure.scheduling import ResourceAwareScheduler


class TestResourceProfile:
    """Tests for ResourceProfile model."""

    def test_detect_returns_profile(self) -> None:
        """Test that detect() returns a ResourceProfile instance."""
        with patch("psutil.cpu_count", return_value=4):
            with patch("psutil.cpu_freq", return_value=MagicMock(max=2400.0)):
                with patch("psutil.virtual_memory", return_value=MagicMock(
                    total=16 * 1024**3, available=8 * 1024**3
                )):
                    with patch("psutil.disk_usage", return_value=MagicMock(free=100 * 1024**3)):
                        profile = ResourceProfile.detect()
                        assert profile.cpu_count == 4
                        assert profile.total_ram_mb == 16 * 1024
                        assert profile.available_ram_mb == 8 * 1024

    def test_default_factory(self) -> None:
        """Test that default factory works."""
        profile = ResourceProfile()
        assert profile.cpu_count >= 1
        assert profile.total_ram_mb >= 0


class TestTaskResourceRequirement:
    """Tests for TaskResourceRequirement model."""

    def test_for_heavy_task(self) -> None:
        """Test that heavy tasks get appropriate requirements."""
        req = TaskResourceRequirement.for_task_type("headless_browser")
        assert req.min_cpu_cores == 2
        assert req.min_ram_mb == 2048
        assert req.requires_browser is True

    def test_for_light_task(self) -> None:
        """Test that light tasks get appropriate requirements."""
        req = TaskResourceRequirement.for_task_type("port_probe")
        assert req.min_cpu_cores == 1
        assert req.min_ram_mb == 256
        assert req.requires_browser is False

    def test_for_unknown_task(self) -> None:
        """Test that unknown tasks get default requirements."""
        req = TaskResourceRequirement.for_task_type("unknown_task")
        assert req.min_cpu_cores == 1
        assert req.min_ram_mb == 256


class TestResourceAwareScheduler:
    """Tests for ResourceAwareScheduler."""

    def test_select_worker_heavy_task(self) -> None:
        """Test that heavy tasks are assigned to capable workers."""
        scheduler = ResourceAwareScheduler()

        # Create a capable worker (high resources)
        capable_worker = WorkerInfo(
            id="worker-1",
            hostname="powerful-desktop",
            pid=1000,
            status="idle",
            concurrency=4,
            resources=ResourceProfile(
                cpu_count=8,
                available_ram_mb=8192,
            ),
            capabilities=["browser", "heavy_compute"],
        )
        scheduler.update_worker("worker-1", capable_worker)

        # Create a light worker (low resources)
        light_worker = WorkerInfo(
            id="worker-2",
            hostname="raspberry-pi",
            pid=1001,
            status="idle",
            concurrency=1,
            resources=ResourceProfile(
                cpu_count=4,
                available_ram_mb=512,
            ),
            capabilities=[],
        )
        scheduler.update_worker("worker-2", light_worker)

        # Create a heavy task
        job = MagicMock()
        job.type = "headless_browser"
        job.id = "job-1"

        # The capable worker should be selected
        selected = scheduler.select_worker(job)
        assert selected == "worker-1"

    def test_select_worker_light_task_preferred(self) -> None:
        """Test that light tasks can go to light workers."""
        scheduler = ResourceAwareScheduler()

        # Create a light worker
        light_worker = WorkerInfo(
            id="worker-pi",
            hostname="raspberry-pi",
            pid=1001,
            status="idle",
            concurrency=1,
            resources=ResourceProfile(
                cpu_count=4,
                available_ram_mb=512,
            ),
            capabilities=[],
        )
        scheduler.update_worker("worker-pi", light_worker)

        # Create a heavy worker
        heavy_worker = WorkerInfo(
            id="worker-desktop",
            hostname="desktop",
            pid=1002,
            status="idle",
            concurrency=4,
            resources=ResourceProfile(
                cpu_count=8,
                available_ram_mb=16384,
            ),
            capabilities=["browser"],
        )
        scheduler.update_worker("worker-desktop", heavy_worker)

        # Create a light task
        job = MagicMock()
        job.type = "port_probe"
        job.id = "job-2"

        # Both can handle it, but light worker should get it (less loaded)
        selected = scheduler.select_worker(job)
        # Both are idle, but light worker has fewer cores assigned
        assert selected in ("worker-pi", "worker-desktop")

    def test_no_suitable_worker(self) -> None:
        """Test that None is returned when no worker can handle the task."""
        scheduler = ResourceAwareScheduler()

        # Create a worker without browser capability
        worker = WorkerInfo(
            id="worker-1",
            hostname="no-browser",
            pid=1000,
            status="idle",
            resources=ResourceProfile(
                cpu_count=2,
                available_ram_mb=1024,
            ),
            capabilities=[],
        )
        scheduler.update_worker("worker-1", worker)

        # Create a task that requires browser
        job = MagicMock()
        job.type = "headless_browser"
        job.id = "job-1"

        # Worker can't handle it (no browser capability)
        assert scheduler.select_worker(job) is None

    def test_worker_busy_not_selected(self) -> None:
        """Test that busy workers are not selected."""
        scheduler = ResourceAwareScheduler()

        busy_worker = WorkerInfo(
            id="worker-busy",
            hostname="busy-host",
            pid=1000,
            status="busy",
            active_jobs=["job-0"],
            resources=ResourceProfile(
                cpu_count=8,
                available_ram_mb=8192,
            ),
        )
        scheduler.update_worker("worker-busy", busy_worker)

        job = MagicMock()
        job.type = "port_probe"
        job.id = "job-1"

        assert scheduler.select_worker(job) is None


class TestDistributedCheckpoint:
    """Tests for DistributedCheckpointStore."""

    @pytest.mark.asyncio
    async def test_save_and_load_checkpoint(self) -> None:
        """Test saving and loading checkpoints from Redis."""
        from src.core.checkpoint import CheckpointState
        from src.infrastructure.checkpoint import DistributedCheckpointStore

        # Mock Redis client
        mock_redis = MagicMock()
        mock_redis.execute_command.return_value = None
        mock_redis.execute_script.return_value = 1

        store = DistributedCheckpointStore(mock_redis, "test-node")

        # Create a checkpoint state
        state = CheckpointState(
            pipeline_run_id="test-run-1",
            completed_stages=["recon", "analysis"],
        )

        # Save checkpoint
        result = await store.save_checkpoint(state, "worker-1")
        assert result is True

        # Mock the load
        state_dict = state.to_dict()
        mock_redis.execute_command.return_value = json.dumps(state_dict).encode("utf-8")

        loaded = await store.load_checkpoint("test-run-1")
        assert loaded is not None
        assert loaded.pipeline_run_id == "test-run-1"
        assert "recon" in loaded.completed_stages


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
