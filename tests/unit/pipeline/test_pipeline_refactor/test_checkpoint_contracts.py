import json
import logging
import time
from pathlib import Path
from unittest.mock import MagicMock
import pytest
from src.core.checkpoint import (
    CheckpointManager,
    CheckpointState,
    StageCheckpointGuard,
    _compute_checksum,
    _serialize_sets,
    attempt_recovery,
    create_checkpoint_manager,
    generate_run_id,
)
from src.core.middleware import (
    OutboundRequestInterceptor,
    ScopeCheckResult,
    ScopeValidator,
    ScopeViolationError,
    create_scope_guard,
    validate_url_scope,
)
from src.core.models.stage_result import (
    PipelineContext,
    StageMetric,
    StageName,
    StageResult,
    StageStatus,
)
from src.core.parsers.nuclei_parser import (
    MITRE_TAG_MAP,
    SEVERITY_SCORES,
    VALID_SEVERITIES,
    NucleiFinding,
    NucleiFindingParser,
    NucleiSeverityMapper,
    parse_nuclei_jsonl,
    parse_nuclei_jsonl_file,
)



class TestCheckpointManager:
    """Tests for CheckpointManager and checkpointing utilities."""

    def test_save_and_load_roundtrip(
        self, checkpoint_manager: CheckpointManager, checkpoint_state: CheckpointState
    ) -> None:
        """Saved checkpoint can be loaded back."""
        path = checkpoint_manager.save(checkpoint_state)
        assert path.exists()

        loaded = checkpoint_manager.load()
        assert loaded is not None
        assert loaded.pipeline_run_id == "test-run-001"
        assert set(loaded.completed_stages) == {"scope", "subdomain_discovery"}
        assert loaded.current_stage == "host_probing"

    def test_atomic_write_uses_temp_file(
        self, checkpoint_manager: CheckpointManager, checkpoint_state: CheckpointState
    ) -> None:
        """Save uses temp file + rename pattern."""
        path = checkpoint_manager.save(checkpoint_state)
        # Temp file should not exist after successful save
        tmp_path = path.with_suffix(".tmp")
        assert not tmp_path.exists()
        assert path.exists()

    def test_checksum_integrity_verification(
        self, checkpoint_manager: CheckpointManager, checkpoint_state: CheckpointState
    ) -> None:
        """Checkpoint checksum verifies integrity."""
        checkpoint_manager.save(checkpoint_state)
        loaded = checkpoint_manager.load()
        assert loaded is not None
        # If checksum failed, load would return None
        assert loaded.pipeline_run_id == checkpoint_state.pipeline_run_id

    def test_checksum_detects_corruption(
        self,
        checkpoint_manager: CheckpointManager,
        checkpoint_state: CheckpointState,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Corrupted checkpoint is detected and load returns None."""
        caplog.set_level(logging.WARNING)
        path = checkpoint_manager.save(checkpoint_state)
        # Corrupt the file
        content = path.read_text()
        content = content.replace('"completed_stages"', '"completed_stages_CORRUPTED"')
        path.write_text(content)

        loaded = checkpoint_manager.load()
        assert loaded is None
        assert any("integrity check failed" in record.message.lower() for record in caplog.records)

    def test_mark_stage_complete(self, checkpoint_manager: CheckpointManager) -> None:
        """mark_stage_complete updates state and persists."""
        checkpoint_manager.mark_stage_complete("scope", {"status": "ok"})
        state = checkpoint_manager.load()
        assert state is not None
        assert "scope" in state.completed_stages
        assert state.stage_results["scope"]["status"] == "ok"
        assert state.current_stage is None

    def test_mark_stage_failed(self, checkpoint_manager: CheckpointManager) -> None:
        """mark_stage_failed records failure details."""
        checkpoint_manager.mark_stage_failed("nuclei_scan", "Tool crashed")
        state = checkpoint_manager.load()
        assert state is not None
        assert state.stage_results["nuclei_scan"]["status"] == "failed"
        assert state.stage_results["nuclei_scan"]["error"] == "Tool crashed"

    def test_should_resume_no_checkpoint(self, tmp_path: Path) -> None:
        """should_resume returns False when no checkpoint exists."""
        manager = CheckpointManager(tmp_path / "cp", "new-run")
        can_resume, state = manager.should_resume()
        assert can_resume is False
        assert state is None

    def test_should_resume_with_checkpoint(self, checkpoint_manager: CheckpointManager) -> None:
        """should_resume returns True when checkpoint exists."""
        checkpoint_manager.mark_stage_complete("scope", {})
        can_resume, state = checkpoint_manager.should_resume()
        assert can_resume is True
        assert state is not None

    def test_get_remaining_stages(self, checkpoint_manager: CheckpointManager) -> None:
        """get_remaining_stages returns uncompleted stages."""
        checkpoint_manager.mark_stage_complete("scope", {})
        checkpoint_manager.mark_stage_complete("subdomain_discovery", {})
        all_stages = ["scope", "subdomain_discovery", "host_probing", "nuclei_scan"]
        remaining = checkpoint_manager.get_remaining_stages(all_stages)
        assert remaining == ["host_probing", "nuclei_scan"]

    def test_cleanup_old_checkpoints(
        self, checkpoint_manager: CheckpointManager, checkpoint_state: CheckpointState
    ) -> None:
        """cleanup_old_checkpoints removes excess files."""
        for i in range(5):
            state = CheckpointState(
                pipeline_run_id="test-run-001",
                checkpoint_version=i + 1,
                completed_stages=[f"stage_{i}"],
            )
            checkpoint_manager.save(state)

        deleted = checkpoint_manager.cleanup_old_checkpoints(keep_last=2)
        assert deleted == 3

        files = list(checkpoint_manager._run_dir.glob("checkpoint_v*.json"))
        assert len(files) == 2

    def test_cleanup_no_op_when_under_limit(
        self, checkpoint_manager: CheckpointManager, checkpoint_state: CheckpointState
    ) -> None:
        """cleanup_old_checkpoints does nothing when under limit."""
        checkpoint_manager.save(checkpoint_state)
        deleted = checkpoint_manager.cleanup_old_checkpoints(keep_last=5)
        assert deleted == 0

    def test_get_checkpoint_history(self, checkpoint_manager: CheckpointManager) -> None:
        """get_checkpoint_history returns metadata for all checkpoints."""
        checkpoint_manager.mark_stage_complete("scope", {})
        checkpoint_manager.mark_stage_complete("subdomain_discovery", {})
        history = checkpoint_manager.get_checkpoint_history()
        assert len(history) == 2
        assert history[0]["version"] == 1
        assert history[1]["version"] == 2
        assert "timestamp" in history[0]
        assert "file" in history[0]

    def test_get_checkpoint_history_empty(self, tmp_path: Path) -> None:
        """get_checkpoint_history returns empty list when no checkpoints."""
        manager = CheckpointManager(tmp_path / "cp", "empty-run")
        assert manager.get_checkpoint_history() == []

    def test_stage_checkpoint_guard_success(self, checkpoint_manager: CheckpointManager) -> None:
        """StageCheckpointGuard marks stage complete on normal exit."""
        with StageCheckpointGuard(checkpoint_manager, "test_stage"):
            pass

        state = checkpoint_manager.load()
        assert state is not None
        assert state.stage_results["test_stage"]["status"] == "completed"
        assert "elapsed_seconds" in state.stage_results["test_stage"]

    def test_stage_checkpoint_guard_failure(self, checkpoint_manager: CheckpointManager) -> None:
        """StageCheckpointGuard marks stage failed on exception."""
        with pytest.raises(ValueError):
            with StageCheckpointGuard(checkpoint_manager, "failing_stage"):
                raise ValueError("Something went wrong")

        state = checkpoint_manager.load()
        assert state is not None
        assert state.stage_results["failing_stage"]["status"] == "failed"
        assert "ValueError" in state.stage_results["failing_stage"]["error"]

    def test_stage_checkpoint_guard_returns_manager(
        self, checkpoint_manager: CheckpointManager
    ) -> None:
        """StageCheckpointGuard __enter__ returns the manager."""
        with StageCheckpointGuard(checkpoint_manager, "test_stage") as mgr:
            assert mgr is checkpoint_manager

    def test_create_checkpoint_manager_helper(self, tmp_path: Path) -> None:
        """create_checkpoint_manager creates manager with standard layout."""
        manager = create_checkpoint_manager(tmp_path, "target1", "run-abc")
        assert manager.run_id == "run-abc"
        assert manager.checkpoint_dir == tmp_path / "target1" / "checkpoints"

    def test_create_checkpoint_manager_generates_run_id(self, tmp_path: Path) -> None:
        """create_checkpoint_manager generates run_id when not provided."""
        manager = create_checkpoint_manager(tmp_path, "target1")
        assert manager.run_id.startswith("run-")
        assert len(manager.run_id) > 10

    def test_generate_run_id_uniqueness(self) -> None:
        """generate_run_id produces unique IDs."""
        ids = {generate_run_id() for _ in range(100)}
        # All IDs should be unique (uuid suffix ensures this)
        assert len(ids) == 100

    def test_generate_run_id_format(self) -> None:
        """generate_run_id produces correctly formatted IDs."""
        run_id = generate_run_id()
        assert run_id.startswith("run-")
        parts = run_id.split("-")
        assert len(parts) == 3
        assert parts[1].isdigit()
        assert len(parts[2]) == 8

    def test_attempt_recovery_across_runs(self, tmp_path: Path) -> None:
        """attempt_recovery finds best checkpoint across multiple runs."""
        # attempt_recovery scans: output_dir / target_name / "checkpoints"
        output_dir = tmp_path / "output"
        target_name = "mytarget"

        mgr1 = create_checkpoint_manager(output_dir, target_name, "run-1")
        mgr1.mark_stage_complete("scope", {})
        time.sleep(0.01)

        mgr2 = create_checkpoint_manager(output_dir, target_name, "run-2")
        mgr2.mark_stage_complete("scope", {})
        mgr2.mark_stage_complete("subdomain_discovery", {})

        can_recover, state = attempt_recovery(output_dir, target_name)
        assert can_recover is True
        assert state is not None
        assert state.pipeline_run_id == "run-2"

    def test_attempt_recovery_no_checkpoints(self, tmp_path: Path) -> None:
        """attempt_recovery returns False when no checkpoints exist."""
        can_recover, state = attempt_recovery(tmp_path, "nonexistent")
        assert can_recover is False
        assert state is None

    def test_checkpoint_version_incrementing(self, checkpoint_manager: CheckpointManager) -> None:
        """Checkpoint version increments on each save."""
        state = CheckpointState(pipeline_run_id="test-run-001", checkpoint_version=0)
        checkpoint_manager.save(state)

        checkpoint_manager.mark_stage_complete("scope", {})
        loaded = checkpoint_manager.load()
        assert loaded is not None
        assert loaded.checkpoint_version == 1

        checkpoint_manager.mark_stage_complete("subdomain_discovery", {})
        loaded = checkpoint_manager.load()
        assert loaded is not None
        assert loaded.checkpoint_version == 2

    def test_load_latest_for_run_different_run_id(self, tmp_path: Path) -> None:
        """load_latest_for_run can load checkpoint for a different run_id."""
        mgr1 = CheckpointManager(tmp_path / "cp", "run-a")
        mgr1.mark_stage_complete("scope", {})

        mgr2 = CheckpointManager(tmp_path / "cp", "run-b")
        mgr2.mark_stage_complete("scope", {})
        mgr2.mark_stage_complete("subdomain_discovery", {})

        # mgr2 loads its own latest
        loaded = mgr2.load_latest_for_run("run-a")
        assert loaded is not None
        assert loaded.pipeline_run_id == "run-a"
        assert "scope" in loaded.completed_stages

    def test_serialization_of_sets_in_checkpoint_state(self) -> None:
        """CheckpointState serializes completed_stages as a list."""
        state = CheckpointState(
            pipeline_run_id="test",
            completed_stages=["b", "a", "c"],
        )
        data = state.to_dict()
        assert isinstance(data["completed_stages"], list)
        assert set(data["completed_stages"]) == {"a", "b", "c"}

    def test_deserialization_of_sets_in_checkpoint_state(self) -> None:
        """CheckpointState.from_dict restores completed_stages."""
        data = {
            "pipeline_run_id": "test",
            "completed_stages": ["scope", "recon"],
            "checkpoint_version": 1,
        }
        state = CheckpointState.from_dict(data)
        # from_dict converts completed_stages to a set
        assert isinstance(state.completed_stages, set)
        assert state.completed_stages == {"scope", "recon"}

    def test_ensure_run_dir_creates_directory(self, checkpoint_manager: CheckpointManager) -> None:
        """_ensure_run_dir creates the run directory."""
        assert not checkpoint_manager._run_dir.exists()
        checkpoint_manager._ensure_run_dir()
        assert checkpoint_manager._run_dir.exists()
        assert checkpoint_manager._run_dir.is_dir()

    def test_compute_checksum_deterministic(self) -> None:
        """_compute_checksum produces same result for same input."""
        data = '{"key": "value"}'
        cs1 = _compute_checksum(data)
        cs2 = _compute_checksum(data)
        assert cs1 == cs2

    def test_serialize_sets_function(self) -> None:
        """_serialize_sets converts sets to sorted lists."""
        data = {"hosts": {"b.com", "a.com"}, "nested": {"inner": {"z", "a"}}}
        result = _serialize_sets(data)
        assert result["hosts"] == ["a.com", "b.com"]
        assert result["nested"]["inner"] == ["a", "z"]