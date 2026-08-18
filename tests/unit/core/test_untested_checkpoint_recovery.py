"""Coverage for previously untested checkpoint recovery helpers."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from src.core.checkpoint.base import CheckpointState
from src.core.checkpoint.recovery import (
    _count_failed_stages,
    _validate_checkpoint_state,
    attempt_recovery,
    generate_run_id,
)


@pytest.mark.unit
def test_generate_run_id_format_and_uniqueness() -> None:
    first = generate_run_id()
    second = generate_run_id()
    assert re.fullmatch(r"run-\d+-[0-9a-f]{8}", first)
    assert first != second


@pytest.mark.unit
def test_validate_checkpoint_state_rejects_bad_shapes() -> None:
    ok = CheckpointState(pipeline_run_id="run-1")
    assert _validate_checkpoint_state(ok) is True
    assert _validate_checkpoint_state("nope") is False  # type: ignore[arg-type]
    empty_id = CheckpointState(pipeline_run_id="")
    assert _validate_checkpoint_state(empty_id) is False
    bad_version = CheckpointState(pipeline_run_id="run-1", checkpoint_version=0)
    assert _validate_checkpoint_state(bad_version) is False
    bad_started = CheckpointState(pipeline_run_id="run-1", started_at=-1.0)
    assert _validate_checkpoint_state(bad_started) is False


@pytest.mark.unit
def test_count_failed_stages_ignores_non_dicts_and_success() -> None:
    state = CheckpointState(
        pipeline_run_id="run-1",
        stage_results={
            "recon": {"status": "failed"},
            "scan": {"status": "ERROR"},
            "report": {"status": "timeout"},
            "ok": {"status": "ok"},
            "weird": "not-a-dict",
        },
    )
    assert _count_failed_stages(state) == 3
    assert _count_failed_stages(CheckpointState(pipeline_run_id="run-1")) == 0


@pytest.mark.unit
def test_attempt_recovery_force_fresh_and_empty_dir(tmp_path: Path) -> None:
    assert attempt_recovery(tmp_path, "target", force_fresh=True) == (False, None)
    assert attempt_recovery(tmp_path, "missing-target") == (False, None)


@pytest.mark.unit
def test_checkpoint_state_roundtrip_preserves_run_id() -> None:
    state = CheckpointState(
        pipeline_run_id="run-xyz",
        completed_stages=["recon"],
        source_node="node-a",
        stage_results={"recon": {"status": "ok"}},
    )
    restored = CheckpointState.from_dict(state.to_dict())
    assert restored.pipeline_run_id == "run-xyz"
    assert "recon" in restored.completed_stages
    assert restored.source_node == "node-a"
    assert _validate_checkpoint_state(restored) is True
