"""Checkpoint autosave health, fencing, and recovery candidate selection.

Acceptance: save() I/O failure → autosave survives → next save succeeds.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest

from src.core.checkpoint.health import (
    CheckpointFencedError,
    RecoveryCandidate,
    is_checkpoint_stale,
    select_recovery_candidate,
)
from src.core.checkpoint.manager import CheckpointData, CheckpointManager, LocalCheckpointStore
from src.core.checkpoint.strategies import CheckpointManager as PipelineCheckpointManager


class _FlakyStore:
    """Fails the first ``fail_times`` save calls, then persists."""

    def __init__(self, fail_times: int = 1) -> None:
        self.fail_times = fail_times
        self.calls = 0
        self.saved: list[CheckpointData] = []

    async def save(self, data: CheckpointData) -> str:
        self.calls += 1
        if self.calls <= self.fail_times:
            raise OSError("simulated disk full")
        self.saved.append(data)
        return f"v{data.version:06d}"

    async def load(self, run_id: str, version: int | None = None) -> CheckpointData | None:
        for item in reversed(self.saved):
            if item.run_id == run_id and (version is None or item.version == version):
                return item
        return None

    async def list_versions(self, run_id: str) -> list[int]:
        return [item.version for item in self.saved if item.run_id == run_id]

    async def delete(self, run_id: str, version: int) -> bool:
        return False

    async def prune(self, run_id: str, keep_last: int) -> int:
        return 0


@pytest.mark.unit
def test_autosave_survives_io_failure_then_succeeds() -> None:
    """save() I/O failure must not kill autosave; the next tick persists."""

    async def _run() -> None:
        store = _FlakyStore(fail_times=1)
        manager = CheckpointManager(
            store,
            "run-autosave",
            retry_attempts=1,
            retry_base_delay=0.0,
        )
        manager.set_stage("recon", {"hosts": 3})
        await manager.auto_save(interval=0.01)

        healthy = False
        for _ in range(40):
            await asyncio.sleep(0.01)
            task = manager._auto_save_task
            assert task is not None
            assert not task.done(), "autosave died after I/O failure"
            if store.saved and manager.health.status == "healthy":
                healthy = True
                break

        await manager.stop_auto_save()
        assert healthy, "autosave never recovered after the simulated I/O failure"
        assert store.calls >= 2
        assert store.saved[-1].stages["recon"]["hosts"] == 3
        assert manager.health.failures >= 1
        assert manager.health.saves >= 1

    asyncio.run(_run())


@pytest.mark.unit
def test_save_retries_then_records_health() -> None:
    async def _run() -> None:
        store = _FlakyStore(fail_times=1)
        manager = CheckpointManager(
            store,
            "run-retry",
            retry_attempts=3,
            retry_base_delay=0.0,
        )
        manager.set_stage("scan", {"ok": True})
        version_id = await manager.save()
        assert version_id == "v000001"
        assert store.calls == 2
        assert manager.health.status == "healthy"
        assert manager.health.failures == 1
        assert manager.health.saves == 1

    asyncio.run(_run())


@pytest.mark.unit
def test_atomic_checkpoint_write_preserves_previous(tmp_path: Path) -> None:
    async def _run() -> None:
        store = LocalCheckpointStore(tmp_path)
        first = CheckpointData(run_id="run-a", version=1, timestamp=1.0, stages={"a": 1})
        await store.save(first)
        path = store._version_file("run-a", 2)
        original = store._version_file("run-a", 1).read_text(encoding="utf-8")

        import builtins

        real_open = builtins.open

        def _failing_open(file: Any, *args: Any, **kwargs: Any) -> Any:
            if "v000002" in str(file) and str(file).endswith(".tmp"):
                raise OSError("crash mid-write")
            return real_open(file, *args, **kwargs)

        with pytest.raises(OSError, match="crash mid-write"):
            builtins.open = _failing_open  # type: ignore[assignment]
            try:
                await store.save(
                    CheckpointData(run_id="run-a", version=2, timestamp=2.0, stages={"a": 2})
                )
            finally:
                builtins.open = real_open

        loaded = await store.load("run-a")
        assert loaded is not None
        assert loaded.version == 1
        assert loaded.stages["a"] == 1
        assert store._version_file("run-a", 1).read_text(encoding="utf-8") == original
        assert not path.exists()

    asyncio.run(_run())


@pytest.mark.unit
def test_stale_detection_requires_dirty_and_age() -> None:
    now = 1_000.0
    assert is_checkpoint_stale(500.0, now=now, max_age_seconds=100.0, dirty=True) is True
    assert is_checkpoint_stale(950.0, now=now, max_age_seconds=100.0, dirty=True) is False
    assert is_checkpoint_stale(500.0, now=now, max_age_seconds=100.0, dirty=False) is False
    assert is_checkpoint_stale(None, now=now, dirty=True) is False


@pytest.mark.unit
def test_local_candidate_preferred_over_stale_remote() -> None:
    local_state = {"id": "local"}
    remote_state = {"id": "remote"}
    chosen = select_recovery_candidate(
        [
            RecoveryCandidate(
                failed_neg=0,
                completed=8,
                timestamp=100.0,
                source_node="node-b",
                state=remote_state,
            ),
            RecoveryCandidate(
                failed_neg=0,
                completed=6,
                timestamp=900.0,
                source_node="node-a",
                state=local_state,
            ),
        ],
        local_node_id="node-a",
        now=1_000.0,
        stale_after_seconds=200.0,
    )
    assert chosen is not None
    assert chosen.state is local_state


@pytest.mark.unit
def test_remote_wins_when_significantly_ahead_and_fresh() -> None:
    local_state = {"id": "local"}
    remote_state = {"id": "remote"}
    chosen = select_recovery_candidate(
        [
            RecoveryCandidate(
                failed_neg=0,
                completed=12,
                timestamp=990.0,
                source_node="node-b",
                state=remote_state,
            ),
            RecoveryCandidate(
                failed_neg=0,
                completed=2,
                timestamp=980.0,
                source_node="node-a",
                state=local_state,
            ),
        ],
        local_node_id="node-a",
        now=1_000.0,
        stale_after_seconds=200.0,
    )
    assert chosen is not None
    assert chosen.state is remote_state


@pytest.mark.unit
def test_fence_rejects_stale_writer() -> None:
    async def _run() -> None:
        store = _FlakyStore(fail_times=0)
        owner = CheckpointManager(store, "run-fence", retry_attempts=1, retry_base_delay=0.0)
        owner.set_stage("recon", {"n": 1})
        await owner.save()

        usurper = CheckpointManager(store, "run-fence", retry_attempts=1, retry_base_delay=0.0)
        usurper.set_stage("recon", {"n": 99})
        with pytest.raises(CheckpointFencedError):
            await usurper.save()
        assert usurper.health.fenced is True
        loaded = await store.load("run-fence")
        assert loaded is not None
        assert loaded.stages["recon"]["n"] == 1

    asyncio.run(_run())


@pytest.mark.unit
def test_pipeline_manager_records_save_health(tmp_path: Path) -> None:
    manager = PipelineCheckpointManager(tmp_path / "checkpoints", "run-pipe")
    from src.core.checkpoint.base import CheckpointState

    state = CheckpointState(pipeline_run_id="run-pipe", checkpoint_version=1)
    manager.save(state)
    assert manager.health.status == "healthy"
    assert manager.health.saves == 1
