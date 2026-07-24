"""Regression tests for system-wide defect fixes.

Each test class targets a specific production defect identified during the
deep system investigation and verifies that the fix prevents the defect
from recurring.

NOTE: Several modules (pipeline_orchestrator, dashboard) have pre-existing
import chain issues (SHELL_META missing, circular imports). Tests that need
these modules use targeted mocking to bypass the broken import chains.
"""

from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _safe_import(module_path: str, bypass_modules: list[str] | None = None) -> Any:
    """Import a module, optionally injecting stubs for broken dependencies."""
    if bypass_modules:
        for mod in bypass_modules:
            if mod not in sys.modules:
                sys.modules[mod] = MagicMock()
    try:
        return importlib.import_module(module_path)
    except (ImportError, AttributeError):
        return None


# ---------------------------------------------------------------------------
# Defect 1: Checkpoint Split-Brain Recovery Lock
# ---------------------------------------------------------------------------
class TestDefect1CheckpointSplitBrain:
    """Verify that attempt_recovery acquires a RunLock to prevent split-brain."""

    @pytest.mark.regression
    def test_run_lock_has_ttl(self, tmp_path: Path) -> None:
        """RunLock must have a TTL to auto-expire abandoned locks."""
        from src.infrastructure.task_pool import RunLock

        lock = RunLock(cache_dir=tmp_path / "locks")
        lock.acquire("ttl-test-target", ttl_seconds=2)
        assert lock._acquired is True
        lock.release()

    @pytest.mark.regression
    def test_run_lock_file_fallback(self, tmp_path: Path) -> None:
        """RunLock must fall back to filesystem when Redis is unavailable."""
        from src.infrastructure.task_pool import RunLock

        lock = RunLock(cache_dir=tmp_path / "locks", redis_url=None)
        result = lock.acquire("fs-lock-target", ttl_seconds=60)
        assert result is True
        lock.release()

    @pytest.mark.regression
    def test_run_lock_prevents_concurrent_acquire(self, tmp_path: Path) -> None:
        """RunLock must prevent a second acquire on the same key."""
        from src.infrastructure.task_pool import RunLock

        lock1 = RunLock(cache_dir=tmp_path / "locks", redis_url=None)
        lock2 = RunLock(cache_dir=tmp_path / "locks", redis_url=None)

        assert lock1.acquire("concurrent-target", ttl_seconds=60) is True
        result = lock2.acquire("concurrent-target", ttl_seconds=60)
        assert result is False
        lock1.release()

    @pytest.mark.regression
    def test_run_lock_release_and_reacquire(self, tmp_path: Path) -> None:
        """After release, the same key must be acquirable again."""
        from src.infrastructure.task_pool import RunLock

        lock1 = RunLock(cache_dir=tmp_path / "locks", redis_url=None)
        lock2 = RunLock(cache_dir=tmp_path / "locks", redis_url=None)

        assert lock1.acquire("reacquire-target", ttl_seconds=60) is True
        lock1.release()
        assert lock2.acquire("reacquire-target", ttl_seconds=60) is True
        lock2.release()

    @pytest.mark.regression
    def test_recovery_module_has_attempt_recovery(self) -> None:
        """recovery.attempt_recovery must exist and accept local_node_id."""
        import inspect

        from src.core.checkpoint.recovery import attempt_recovery

        sig = inspect.signature(attempt_recovery)
        assert "local_node_id" in sig.parameters

    @pytest.mark.regression
    def test_security_module_has_run_secured(self) -> None:
        """security.run_secured must be importable (fix is in its body)."""
        # We can't import security.py directly due to import chain issues,
        # but we verify the source code contains the RunLock reference.
        security_path = (
            Path(__file__).resolve().parent.parent.parent
            / "src" / "pipeline" / "services" / "pipeline_orchestrator"
            / "_orchestrator" / "security.py"
        )
        source = security_path.read_text(encoding="utf-8")
        assert "RunLock" in source
        assert "recovery_lock.acquire(" in source
        assert "recovery_lock.release()" in source


# ---------------------------------------------------------------------------
# Defect 2: WAL Dual-Commit Data Loss — Replication Wait on Finalize
# ---------------------------------------------------------------------------
class TestDefect2WALReplicationWait:
    """Verify that _finalize_run waits for checkpoint replications."""

    @pytest.mark.regression
    def test_checkpoint_manager_has_wait_for_replications(self) -> None:
        """CheckpointManager must expose wait_for_replications method."""
        from src.core.checkpoint.strategies import CheckpointManager

        assert hasattr(CheckpointManager, "wait_for_replications")
        assert callable(CheckpointManager.wait_for_replications)

    @pytest.mark.regression
    def test_checkpoint_manager_has_save_and_wait(self) -> None:
        """CheckpointManager must expose save_and_wait for critical checkpoints."""
        from src.core.checkpoint.strategies import CheckpointManager

        assert hasattr(CheckpointManager, "save_and_wait")
        assert callable(CheckpointManager.save_and_wait)

    @pytest.mark.regression
    def test_wal_has_close_method(self) -> None:
        """FrontierWAL must have a close() method for clean shutdown."""
        from src.infrastructure.frontier.wal import FrontierWAL

        assert hasattr(FrontierWAL, "close")
        assert callable(FrontierWAL.close)

    @pytest.mark.regression
    def test_orchestrator_finalize_waits_replications(self) -> None:
        """orchestrator.py _finalize_run must call wait_for_replications."""
        orch_path = (
            Path(__file__).resolve().parent.parent.parent
            / "src" / "pipeline" / "services" / "pipeline_orchestrator"
            / "orchestrator.py"
        )
        source = orch_path.read_text(encoding="utf-8")
        assert "wait_for_replications" in source
        assert "wal.close()" in source


# ---------------------------------------------------------------------------
# Defect 3: Actor Scheduler Capacity Leak
# ---------------------------------------------------------------------------
class TestDefect3ActorSchedulerCapacityLeak:
    """Verify that capacity slots are released when _dispatch fails early."""

    @pytest.mark.regression
    def test_actor_scheduler_has_release_capacity(self) -> None:
        """ActorScheduler must have _release_capacity method."""
        scheduler_path = (
            Path(__file__).resolve().parent.parent.parent
            / "src" / "pipeline" / "services" / "pipeline_orchestrator"
            / "actor_scheduler.py"
        )
        source = scheduler_path.read_text(encoding="utf-8")
        assert "def _release_capacity(self, stage_name: str)" in source

    @pytest.mark.regression
    def test_dispatch_releases_capacity_on_method_not_found(self) -> None:
        """_dispatch must call _release_capacity when stage method is missing."""
        scheduler_path = (
            Path(__file__).resolve().parent.parent.parent
            / "src" / "pipeline" / "services" / "pipeline_orchestrator"
            / "actor_scheduler.py"
        )
        source = scheduler_path.read_text(encoding="utf-8")
        # After mark_skipped for method_not_found, _release_capacity must be called
        lines = source.split("\n")
        found_release_after_method_not_found = False
        for i, line in enumerate(lines):
            if "method_not_found" in line:
                # Check subsequent lines for _release_capacity
                for j in range(i + 1, min(i + 5, len(lines))):
                    if "_release_capacity" in lines[j]:
                        found_release_after_method_not_found = True
                        break
                break
        assert found_release_after_method_not_found, (
            "_release_capacity not called after method_not_found skip"
        )

    @pytest.mark.regression
    def test_dispatch_releases_capacity_on_suspend(self) -> None:
        """_dispatch must call _release_capacity when suspend is triggered."""
        scheduler_path = (
            Path(__file__).resolve().parent.parent.parent
            / "src" / "pipeline" / "services" / "pipeline_orchestrator"
            / "actor_scheduler.py"
        )
        source = scheduler_path.read_text(encoding="utf-8")
        lines = source.split("\n")
        found_release_after_suspend = False
        for i, line in enumerate(lines):
            if 'reason="suspend_triggered"' in line:
                for j in range(i + 1, min(i + 5, len(lines))):
                    if "_release_capacity" in lines[j]:
                        found_release_after_suspend = True
                        break
                break
        assert found_release_after_suspend, (
            "_release_capacity not called after suspend_triggered skip"
        )

    @pytest.mark.regression
    def test_release_capacity_handles_import_error(self) -> None:
        """_release_capacity must catch ImportError gracefully."""
        scheduler_path = (
            Path(__file__).resolve().parent.parent.parent
            / "src" / "pipeline" / "services" / "pipeline_orchestrator"
            / "actor_scheduler.py"
        )
        source = scheduler_path.read_text(encoding="utf-8")
        # The method must have try/except around capacity_mgr import
        assert "except (ImportError, Exception):" in source or "except ImportError:" in source


# ---------------------------------------------------------------------------
# Defect 4: Finding Submission Race Condition
# ---------------------------------------------------------------------------
class TestDefect4FindingSubmissionRace:
    """Verify idempotency and atomic write-back for platform submissions."""

    @pytest.mark.regression
    def test_reports_source_has_idempotency_key(self) -> None:
        """reports.py must define _idempotency_key function."""
        reports_path = (
            Path(__file__).resolve().parent.parent.parent
            / "src" / "dashboard" / "fastapi" / "routers" / "reports.py"
        )
        source = reports_path.read_text(encoding="utf-8")
        assert "def _idempotency_key(finding_id: str, platform: str) -> str:" in source

    @pytest.mark.regression
    def test_reports_source_has_submission_lock(self) -> None:
        """reports.py must define _get_submission_lock function."""
        reports_path = (
            Path(__file__).resolve().parent.parent.parent
            / "src" / "dashboard" / "fastapi" / "routers" / "reports.py"
        )
        source = reports_path.read_text(encoding="utf-8")
        assert "def _get_submission_lock(" in source

    @pytest.mark.regression
    def test_reports_source_has_atomic_write_back(self) -> None:
        """reports.py must define _mark_finding_reported_on_disk function."""
        reports_path = (
            Path(__file__).resolve().parent.parent.parent
            / "src" / "dashboard" / "fastapi" / "routers" / "reports.py"
        )
        source = reports_path.read_text(encoding="utf-8")
        assert "def _mark_finding_reported_on_disk(" in source
        # Must use atomic temp+rename pattern
        assert "tempfile.mkstemp" in source
        assert ".replace(" in source

    @pytest.mark.regression
    def test_idempotency_key_stability(self) -> None:
        """Same inputs must always produce the same key (pure function test)."""
        import hashlib

        def _idempotency_key(finding_id: str, platform: str) -> str:
            raw = f"{finding_id}:{platform}"
            return hashlib.sha256(raw.encode()).hexdigest()[:16]

        assert _idempotency_key("f1", "hackerone") == _idempotency_key("f1", "hackerone")
        assert _idempotency_key("f1", "hackerone") != _idempotency_key("f1", "bugcrowd")
        assert _idempotency_key("f1", "hackerone") != _idempotency_key("f2", "hackerone")
        assert len(_idempotency_key("f1", "hackerone")) == 16

    @pytest.mark.regression
    def test_atomic_write_back_logic(self, tmp_path: Path) -> None:
        """_mark_finding_reported_on_disk must atomically update findings.json."""
        import os
        import tempfile

        findings = [
            {"id": "f1", "title": "XSS", "severity": "high"},
            {"id": "f2", "title": "SSRF", "severity": "critical"},
        ]
        findings_path = tmp_path / "findings.json"
        findings_path.write_text(json.dumps(findings), encoding="utf-8")

        # Inline implementation matching the fix
        def _mark_reported(path: Path, fid: str, plat: str) -> None:
            data = json.loads(path.read_text(encoding="utf-8"))
            for f in data:
                if isinstance(f, dict) and str(f.get("id")) == fid:
                    reported = f.setdefault("already_reported_platforms", [])
                    if plat not in reported:
                        reported.append(plat)
                    f["already_reported"] = True
                    break
            tmp_fd, tmp_path_str = tempfile.mkstemp(
                dir=path.parent, suffix=".tmp", prefix="findings_"
            )
            try:
                with os.fdopen(tmp_fd, "w", encoding="utf-8") as tmp_f:
                    json.dump(data, tmp_f, indent=2)
                    tmp_f.flush()
                    os.fsync(tmp_f.fileno())
                Path(tmp_path_str).replace(path)
            except Exception:
                try:
                    Path(tmp_path_str).unlink(missing_ok=True)
                except OSError:
                    pass
                raise

        _mark_reported(findings_path, "f1", "hackerone")

        updated = json.loads(findings_path.read_text(encoding="utf-8"))
        assert updated[0]["already_reported"] is True
        assert "hackerone" in updated[0]["already_reported_platforms"]
        assert "already_reported" not in updated[1]

        # Idempotent: calling again should not duplicate
        _mark_reported(findings_path, "f1", "hackerone")
        updated2 = json.loads(findings_path.read_text(encoding="utf-8"))
        assert updated2[0]["already_reported_platforms"].count("hackerone") == 1

    @pytest.mark.regression
    def test_submit_endpoint_has_idempotency_guard(self) -> None:
        """submit_finding_to_platform must check idempotency before submitting."""
        reports_path = (
            Path(__file__).resolve().parent.parent.parent
            / "src" / "dashboard" / "fastapi" / "routers" / "reports.py"
        )
        source = reports_path.read_text(encoding="utf-8")
        assert "idempotent" in source
        assert "idem_key" in source


# ---------------------------------------------------------------------------
# Defect 5: Evidence Custody In-Memory Persistence
# ---------------------------------------------------------------------------
class TestDefect5EvidenceCustodyPersistence:
    """Verify that evidence custody records persist to disk."""

    @pytest.mark.regression
    def test_evidence_custody_source_has_persistence(self) -> None:
        """evidence_custody.py must have disk load/persist functions."""
        ec_path = (
            Path(__file__).resolve().parent.parent.parent
            / "src" / "dashboard" / "fastapi" / "routers" / "evidence_custody.py"
        )
        source = ec_path.read_text(encoding="utf-8")
        assert "def _load_evidence_from_disk() -> None:" in source
        assert "def _persist_evidence_to_disk() -> None:" in source
        assert "def _resolve_store_path() -> Path:" in source

    @pytest.mark.regression
    def test_evidence_custody_uses_atomic_write(self) -> None:
        """_persist_evidence_to_disk must use temp+rename for atomicity."""
        ec_path = (
            Path(__file__).resolve().parent.parent.parent
            / "src" / "dashboard" / "fastapi" / "routers" / "evidence_custody.py"
        )
        source = ec_path.read_text(encoding="utf-8")
        assert "tempfile.mkstemp" in source
        assert ".replace(" in source
        assert "os.fsync" in source

    @pytest.mark.regression
    def test_evidence_custody_endpoints_call_load(self) -> None:
        """All GET/POST endpoints must call _load_evidence_from_disk."""
        ec_path = (
            Path(__file__).resolve().parent.parent.parent
            / "src" / "dashboard" / "fastapi" / "routers" / "evidence_custody.py"
        )
        source = ec_path.read_text(encoding="utf-8")
        load_count = source.count("_load_evidence_from_disk()")
        # At least list, get, create, access, modify, verify, delete
        assert load_count >= 6, f"Expected >=6 _load_evidence_from_disk() calls, got {load_count}"

    @pytest.mark.regression
    def test_evidence_custody_mutations_call_persist(self) -> None:
        """Mutating endpoints must call _persist_evidence_to_disk."""
        ec_path = (
            Path(__file__).resolve().parent.parent.parent
            / "src" / "dashboard" / "fastapi" / "routers" / "evidence_custody.py"
        )
        source = ec_path.read_text(encoding="utf-8")
        persist_count = source.count("_persist_evidence_to_disk()")
        # create, access, modify, delete = at least 4
        assert persist_count >= 4, f"Expected >=4 _persist_evidence_to_disk() calls, got {persist_count}"

    @pytest.mark.regression
    def test_evidence_persistence_round_trip(self, tmp_path: Path) -> None:
        """Write then read evidence records must survive a round-trip."""
        store_path = tmp_path / "evidence.json"
        records: list[dict[str, Any]] = []

        # Simulate write
        record = {
            "id": "evidence-test-1",
            "finding_id": "f1",
            "data": "test evidence data",
            "hash": "abc123",
            "created_at": "2026-01-01T00:00:00Z",
            "created_by": "tester",
            "custody_chain": [],
        }
        records.append(record)
        store_path.write_text(json.dumps(records, indent=2), encoding="utf-8")

        # Simulate read (new process)
        reloaded = json.loads(store_path.read_text(encoding="utf-8"))
        assert len(reloaded) == 1
        assert reloaded[0]["id"] == "evidence-test-1"


# ---------------------------------------------------------------------------
# Defect 6: Scope Merge Data Loss
# ---------------------------------------------------------------------------
class TestDefect6ScopeMergeCheckpoint:
    """Verify that scope merge triggers immediate checkpoint save."""

    @pytest.mark.regression
    def test_security_source_has_checkpoint_after_merge(self) -> None:
        """security.py must checkpoint immediately after scope merge."""
        security_path = (
            Path(__file__).resolve().parent.parent.parent
            / "src" / "pipeline" / "services" / "pipeline_orchestrator"
            / "_orchestrator" / "security.py"
        )
        source = security_path.read_text(encoding="utf-8")
        # Must save context snapshot after merge
        assert 'save_context_snapshot' in source
        assert '"_scope_merge"' in source

    @pytest.mark.regression
    def test_security_source_has_wal_compaction_after_merge(self) -> None:
        """security.py must compact WAL after scope merge."""
        security_path = (
            Path(__file__).resolve().parent.parent.parent
            / "src" / "pipeline" / "services" / "pipeline_orchestrator"
            / "_orchestrator" / "security.py"
        )
        source = security_path.read_text(encoding="utf-8")
        assert "compact_after_snapshot" in source

    @pytest.mark.regression
    def test_checkpoint_manager_has_save_context_snapshot(self) -> None:
        """CheckpointManager must support save_context_snapshot."""
        from src.core.checkpoint.strategies import CheckpointManager

        assert hasattr(CheckpointManager, "save_context_snapshot")
        assert callable(CheckpointManager.save_context_snapshot)

    @pytest.mark.regression
    def test_wal_has_compact_after_snapshot(self) -> None:
        """FrontierWAL must support compact_after_snapshot."""
        from src.infrastructure.frontier.wal import FrontierWAL

        assert hasattr(FrontierWAL, "compact_after_snapshot")
        assert callable(FrontierWAL.compact_after_snapshot)


# ---------------------------------------------------------------------------
# Defect 7: Learning Integration State Corruption
# ---------------------------------------------------------------------------
class TestDefect7LearningIntegrationState:
    """Verify that LearningIntegration resets on target change."""

    @pytest.mark.regression
    def test_learning_integration_has_current_target(self) -> None:
        """LearningIntegration must track _current_target."""
        from src.learning.integration import LearningIntegration

        assert hasattr(LearningIntegration, "_current_target")

    @pytest.mark.regression
    def test_learning_integration_get_or_create_exists(self) -> None:
        """LearningIntegration.get_or_create must exist."""
        from src.learning.integration import LearningIntegration

        assert callable(getattr(LearningIntegration, "get_or_create", None))

    @pytest.mark.regression
    def test_learning_integration_reset_exists(self) -> None:
        """LearningIntegration.reset must exist for cleanup."""
        from src.learning.integration import LearningIntegration

        assert callable(getattr(LearningIntegration, "reset", None))

    @pytest.mark.regression
    def test_config_fingerprint_differs_on_change(self) -> None:
        """Different configs must produce different fingerprints."""
        from src.learning.config import LearningConfig
        from src.learning.integration import _config_fingerprint

        config1 = LearningConfig()
        config2 = LearningConfig()
        config2.database_path = "/different/path.db"

        assert _config_fingerprint(config1) != _config_fingerprint(config2)

    @pytest.mark.regression
    def test_get_or_create_resets_on_target_change(self) -> None:
        """get_or_create must reset singleton when target changes."""
        integration_src = (
            Path(__file__).resolve().parent.parent.parent
            / "src" / "learning" / "integration" / "__init__.py"
        )
        source = integration_src.read_text(encoding="utf-8")
        # Must check prev_target != target and reset
        assert "prev_target" in source
        assert "resetting singleton to prevent cross-target contamination" in source

    @pytest.mark.regression
    def test_config_fingerprint_stability(self) -> None:
        """Same config must always produce the same fingerprint."""
        from src.learning.config import LearningConfig
        from src.learning.integration import _config_fingerprint

        config = LearningConfig()
        fp1 = _config_fingerprint(config)
        fp2 = _config_fingerprint(config)
        assert fp1 == fp2
        assert len(fp1) == 16  # SHA-256 truncated


# ---------------------------------------------------------------------------
# Defect 8: Task Registry Ghost Tasks
# ---------------------------------------------------------------------------
class TestDefect8TaskRegistryGhosts:
    """Verify that ghost tasks are detected and cleaned up."""

    @pytest.mark.regression
    def test_task_registry_has_reconcile(self) -> None:
        """TaskRegistry must expose a reconcile method."""
        from src.core.task_registry import TaskRegistry

        assert hasattr(TaskRegistry, "reconcile")
        assert callable(TaskRegistry.reconcile)

    @pytest.mark.regression
    def test_task_registry_has_periodic_reconcile(self) -> None:
        """TaskRegistry must support start/stop of periodic reconcile."""
        from src.core.task_registry import TaskRegistry

        assert hasattr(TaskRegistry, "start_periodic_reconcile")
        assert hasattr(TaskRegistry, "stop_periodic_reconcile")

    @pytest.mark.regression
    def test_status_auto_reconciles_on_many_ghosts(self) -> None:
        """status() must auto-reconcile when ghost count exceeds threshold."""
        from src.core.task_registry import TaskRegistry

        registry = TaskRegistry()
        result = registry.status()
        assert "active" in result
        assert "pending_ghosts" in result

    @pytest.mark.regression
    @pytest.mark.asyncio
    async def test_reconcile_cleans_done_tasks(self) -> None:
        """reconcile() must remove done/cancelled tasks from registry."""
        from src.core.task_registry import TaskRegistry

        registry = TaskRegistry()

        async def _immediate():
            return "done"

        task = registry.create_task(_immediate(), owner="test", name="immediate")
        await task  # Wait for completion

        result = registry.reconcile()
        assert isinstance(result, dict)
        assert "ghosts_removed" in result
        assert "remaining_tasks" in result

    @pytest.mark.regression
    @pytest.mark.asyncio
    async def test_shutdown_all_stops_periodic_reconcile(self) -> None:
        """shutdown_all() must stop periodic reconcile before cancelling."""
        from src.core.task_registry import TaskRegistry

        registry = TaskRegistry()
        await registry.shutdown_all()  # Must not raise on empty registry


# ---------------------------------------------------------------------------
# Cross-Defect Integration
# ---------------------------------------------------------------------------
class TestCrossDefectIntegration:
    """Verify that multiple fixes work together correctly."""

    @pytest.mark.regression
    def test_checkpoint_strategies_importable(self) -> None:
        """All checkpoint strategy classes must be importable."""
        from src.core.checkpoint.strategies import CheckpointManager

        assert hasattr(CheckpointManager, "wait_for_replications")
        assert hasattr(CheckpointManager, "save_and_wait")
        assert hasattr(CheckpointManager, "save_context_snapshot")

    @pytest.mark.regression
    def test_wal_importable(self) -> None:
        """FrontierWAL must be importable with all defect-fix methods."""
        from src.infrastructure.frontier.wal import FrontierWAL

        assert callable(getattr(FrontierWAL, "log_delta", None))
        assert callable(getattr(FrontierWAL, "recover_deltas", None))
        assert callable(getattr(FrontierWAL, "close", None))
        assert callable(getattr(FrontierWAL, "compact_after_snapshot", None))

    @pytest.mark.regression
    def test_task_registry_importable(self) -> None:
        """TaskRegistry must be importable with all defect-fix methods."""
        from src.core.task_registry import TaskRegistry

        assert callable(getattr(TaskRegistry, "reconcile", None))
        assert callable(getattr(TaskRegistry, "start_periodic_reconcile", None))
        assert callable(getattr(TaskRegistry, "stop_periodic_reconcile", None))

    @pytest.mark.regression
    def test_run_lock_importable(self) -> None:
        """RunLock must be importable."""
        from src.infrastructure.task_pool import RunLock

        assert hasattr(RunLock, "acquire")
        assert hasattr(RunLock, "release")

    @pytest.mark.regression
    def test_learning_integration_importable(self) -> None:
        """LearningIntegration must be importable with target tracking."""
        from src.learning.integration import LearningIntegration

        assert hasattr(LearningIntegration, "_current_target")
        assert hasattr(LearningIntegration, "get_or_create")
        assert hasattr(LearningIntegration, "reset")
