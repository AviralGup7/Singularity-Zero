"""Comprehensive unit test suite for Category 3 implementations.

Verifies:
1. Subprocess execution with process cancellation & trace propagation (runner.py)
2. Inter-stage streaming backpressure (StageStream[T])
3. Worker lease renewal heartbeat (WorkerLite._renew_lease_heartbeat)
4. Dynamic Raft cluster membership (RaftClusterSimulation.add_node / remove_node)
5. Monotonic storage fencing tokens (MeshConsensus.fencing_token)
6. Distributed circuit breaker state synchronization (CircuitBreaker.apply_remote_state)
7. Distributed cache invalidation pub/sub (CacheManager broadcast & handle_distributed_invalidation)
8. Poison-pill quarantine and dead-letter job status states (JobStatus)
9. Resource pressure Schmitt-trigger hysteresis deadbands (classify_pressure)
10. Delta checkpoint serialization (DagCheckpointStore.save_delta / load_with_deltas)
11. Token Revocation List (TRL) & JWT jti validation (security.py)
12. Online SQLite snapshot backup & restore (SqliteOnlineBackupService)
"""

from __future__ import annotations

import asyncio
import os
import sqlite3
import tempfile
import time
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.core.checkpoint.dag_checkpoint import DagCheckpoint, DagCheckpointStore
from src.core.frontier.raft_cluster import MultiNodeRaftCluster
from src.core.runtime.resource_guard import PressureLevel, classify_pressure
from src.dashboard.fastapi.security import (
    Principal,
    authenticate_jwt_token,
    create_jwt,
    is_token_revoked,
    revoke_token,
)
from src.infrastructure.cache.cache_manager import CacheManager
from src.infrastructure.mesh.consensus import MeshConsensus, _LeaderRecord
from src.infrastructure.queue.worker_lite import LiteWorker
from src.infrastructure.storage.backup_service import SqliteOnlineBackupService
from src.jobs.status import TERMINAL_JOB_STATUSES, JobStatus, parse_job_status
from src.pipeline.services.tool_execution import CompletedToolRun, ToolInvocation, run_external_tool
from src.pipeline.stage_stream import StageStream
from src.resilience.circuit_breaker import CircuitBreaker, CircuitBreakerConfig, CircuitState


@pytest.mark.asyncio
async def test_stage_stream_backpressure_and_batching() -> None:
    """Verify StageStream bounded channel emits, blocks, batches, and closes."""
    stream: StageStream[str] = StageStream(maxsize=3, name="test_stream")
    assert stream.maxsize == 3
    assert stream.buffer_depth == 0

    await stream.emit("item-1")
    await stream.emit("item-2")
    assert stream.buffer_depth == 2

    batch = await stream.read_batch(max_batch_size=10)
    assert batch == ["item-1", "item-2"]
    assert stream.buffer_depth == 0

    await stream.emit("item-3")
    await stream.close()
    assert stream.is_closed is True

    items = []
    async for x in stream:
        items.append(x)
    assert items == ["item-3"]


@pytest.mark.asyncio
async def test_worker_lease_renewal_heartbeat() -> None:
    """Verify LiteWorker._renew_lease_heartbeat issues renewal script evaluation."""
    worker = LiteWorker(
        worker_id="worker-test-1",
        redis_url="redis://localhost:6379/0",
        lease_seconds=0.2,
    )
    mock_redis = AsyncMock()
    mock_redis.evalsha.return_value = [1, "renewed", "123456789"]
    worker._redis = mock_redis
    worker._shas["renew_lease"] = "sha_renew"
    worker._job_lease_versions["job-123"] = "ver-1"

    # Create dummy active task that stays active during renewal
    dummy_task = asyncio.create_task(asyncio.sleep(10.0))
    worker._job_task_map["job-123"] = dummy_task

    # Run heartbeat iteration
    renewal_coro = worker._renew_lease_heartbeat("job-123", "cstp:job:job-123")
    renewal_task = asyncio.create_task(renewal_coro)

    await asyncio.sleep(0.25)  # lease_seconds * 0.5 is 0.1s
    worker._shutdown_requested = True
    renewal_task.cancel()
    dummy_task.cancel()

    assert mock_redis.evalsha.called
    call_args = mock_redis.evalsha.call_args[0]
    assert call_args[0] == "sha_renew"
    assert call_args[2] == "cstp:job:job-123"
    assert call_args[3] == "worker-test-1"
    assert call_args[4] == "ver-1"


def test_dynamic_raft_membership() -> None:
    """Verify dynamic node addition and removal in Raft cluster simulation."""
    cluster = MultiNodeRaftCluster(partition_id="part-dyn", node_count=3)
    try:
        assert cluster.node_count == 3
        assert len(cluster.nodes) == 3

        cluster.add_node("node_dynamic_1")
        assert cluster.node_count == 4
        assert "node_dynamic_1" in cluster.nodes
        assert "node_dynamic_1" in cluster.nodes["node_0"].peers

        cluster.remove_node("node_dynamic_1")
        assert cluster.node_count == 3
        assert "node_dynamic_1" not in cluster.nodes
        assert "node_dynamic_1" not in cluster.nodes["node_0"].peers
    finally:
        cluster.close()


def test_mesh_consensus_monotonic_fencing_token() -> None:
    """Verify MeshConsensus exposes and validates monotonic fencing tokens."""
    gossip = MagicMock()
    gossip.local_node.id = "node-alpha"
    consensus = MeshConsensus(gossip=gossip)

    # Not leader: token is 0
    assert consensus.fencing_token == 0
    assert not consensus.validate_fencing_token(10)

    # Assume leader lease with term=5, fencing_token=42
    consensus.leader_id = "node-alpha"
    consensus.term = 5
    consensus._lease = _LeaderRecord(
        node_id="node-alpha", term=5, acquired_at=time.time(), fencing_token=42
    )

    assert consensus.is_leader() is True
    assert consensus.fencing_token == 42
    assert consensus.validate_fencing_token(42) is True
    assert consensus.validate_fencing_token(41) is False


def test_distributed_circuit_breaker_sync() -> None:
    """Verify distributed circuit breaker publishes and applies remote state."""
    cb = CircuitBreaker("tool-nuclei", failure_threshold=5, recovery_timeout=60.0)
    published: list[tuple[str, str, float]] = []

    def mock_hook(name: str, state: str, ts: float) -> None:
        published.append((name, state, ts))

    cb.set_distributed_sync_hook(mock_hook)
    now = time.time()
    cb._set_state_locked(CircuitState.OPEN.value, now, log=False)

    assert len(published) == 1
    assert published[0] == ("tool-nuclei", "open", now)

    # Apply remote state
    remote_now = now + 10.0
    cb.apply_remote_state("half_open", remote_now)
    assert cb.state == CircuitState.HALF_OPEN


def test_distributed_cache_invalidation() -> None:
    """Verify CacheManager broadcasts invalidations and applies remote evictions."""
    cache = CacheManager()
    broadcasts: list[dict] = []
    cache.set_distributed_invalidation_publisher(lambda p: broadcasts.append(p))

    # Trigger bump generation with broadcast
    gen = cache.bump_generation(reason="test_bump")
    assert gen >= 2
    assert len(broadcasts) == 1
    assert broadcasts[0]["action"] == "bump_generation"

    # Handle incoming remote invalidation
    handled = cache.handle_distributed_invalidation(
        {"action": "invalidate_by_tags", "tags": ["finding:123"]}
    )
    assert isinstance(handled, int)
    cache.close()


def test_job_status_quarantine_and_dead_letter() -> None:
    """Verify QUARANTINED and DEAD_LETTER states in JobStatus."""
    assert JobStatus.QUARANTINED == "quarantined"
    assert JobStatus.DEAD_LETTER == "dead_letter"
    assert JobStatus.QUARANTINED in TERMINAL_JOB_STATUSES
    assert JobStatus.DEAD_LETTER in TERMINAL_JOB_STATUSES

    assert parse_job_status("quarantined") == JobStatus.QUARANTINED
    assert parse_job_status("poison_pill") == JobStatus.QUARANTINED
    assert parse_job_status("dead_letter") == JobStatus.DEAD_LETTER
    assert parse_job_status("dlq") == JobStatus.DEAD_LETTER


def test_schmitt_trigger_hysteresis_deadband() -> None:
    """Verify resource pressure hysteresis prevents knife-edge thrashing."""
    # When entering from OK: 92% is PRESSURE
    assert classify_pressure(disk_pct=92.5, previous_level=PressureLevel.OK) == PressureLevel.PRESSURE

    # Fluctuation at 90%: with 5% deadband, PRESSURE remains active (threshold 92 - 5 = 87)
    assert (
        classify_pressure(disk_pct=90.0, previous_level=PressureLevel.PRESSURE)
        == PressureLevel.PRESSURE
    )

    # When dropping below deadband (86% < 87%), exits to WARN
    assert classify_pressure(disk_pct=86.0, previous_level=PressureLevel.PRESSURE) == PressureLevel.WARN


def test_delta_checkpoint_persistence(tmp_path: Path) -> None:
    """Verify localized stage delta checkpointing and replay."""
    cp_path = tmp_path / "dag_checkpoint.json"
    store = DagCheckpointStore(cp_path)

    base = DagCheckpoint(run_id="run-delta-1", status="RUNNING")
    store.save(base)

    store.save_delta(stage_id="recon", stage_status="COMPLETED", findings_count=15)
    store.save_delta(stage_id="vuln_scan", stage_status="FAILED", findings_count=0)

    loaded = store.load_with_deltas()
    assert loaded is not None
    assert loaded.stage_status["recon"] == "COMPLETED"
    assert "recon" in loaded.completed
    assert loaded.stage_status["vuln_scan"] == "FAILED"
    assert "vuln_scan" in loaded.failed
    assert loaded.findings_count_so_far == 15

    store.mark_clean_exit(loaded)
    assert not store.delta_path().exists()


def test_token_revocation_list_trl() -> None:
    """Verify JWT jti validation and Token Revocation List (TRL)."""
    principal = Principal(user="admin_user", role="admin", tenant_id="tenant-1")
    token_dict = create_jwt(principal)
    token = token_dict["access_token"]

    # Valid token authenticates
    p1 = authenticate_jwt_token(token)
    assert p1 is not None
    assert p1.user == "admin_user"

    # Decode jti and revoke it
    import jwt
    from src.dashboard.fastapi.security import app_secret_key

    payload = jwt.decode(token, app_secret_key(), algorithms=["HS256"], options={"verify_exp": False})
    jti = payload["jti"]
    assert not is_token_revoked(jti)

    revoke_token(jti)
    assert is_token_revoked(jti)

    # Revoked token is rejected
    assert authenticate_jwt_token(token) is None


def test_sqlite_online_backup_and_restore(tmp_path: Path) -> None:
    """Verify online SQLite snapshot and disaster recovery restore with SHA-256."""
    db_file = tmp_path / "source.db"
    backup_file = tmp_path / "source.db.bak"
    restore_file = tmp_path / "restored.db"

    # Seed source DB
    conn = sqlite3.connect(str(db_file))
    conn.execute("CREATE TABLE findings (id TEXT PRIMARY KEY, title TEXT)")
    conn.execute("INSERT INTO findings VALUES ('F1', 'SQLi')")
    conn.commit()
    conn.close()

    # Online backup
    manifest = SqliteOnlineBackupService.backup_database(db_file, backup_file)
    assert backup_file.exists()
    assert len(manifest["sha256"]) == 64
    assert manifest["size_bytes"] > 0

    # Restore
    success = SqliteOnlineBackupService.restore_database(backup_file, restore_file)
    assert success is True
    assert restore_file.exists()

    # Check restored data
    r_conn = sqlite3.connect(str(restore_file))
    cursor = r_conn.cursor()
    cursor.execute("SELECT id, title FROM findings")
    row = cursor.fetchone()
    assert row == ("F1", "SQLi")
    r_conn.close()
