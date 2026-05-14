import argparse
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from src.core.checkpoint import CheckpointManager, CheckpointState, StageCheckpointGuard
from src.pipeline.services.pipeline_orchestrator import orchestrator as orch_mod
from src.pipeline.services.pipeline_orchestrator.orchestrator import PipelineOrchestrator


class _DummyOutputStore:
    def __init__(self, root: Path) -> None:
        self.target_root = root / "target"
        self.target_root.mkdir(parents=True, exist_ok=True)
        self.run_dir = self.target_root / "run-1"
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.cache_root = self.target_root / "cache"
        self.cache_root.mkdir(parents=True, exist_ok=True)

    def write_scope(self, _scope_entries: list[str]) -> None:
        return None


class _NoopCheckpointGuard:
    def __init__(self, _manager: object, _stage_name: str) -> None:
        pass

    def __enter__(self) -> object:
        return self

    def __exit__(self, _exc_type: object, _exc: object, _tb: object) -> bool:
        return False


class _DummyLearning:
    def compute_adaptations(self, _ctx: dict[str, object]) -> list[object]:
        return []

    def apply_adaptations(self, _ctx: dict[str, object], _adaptations: list[object]) -> None:
        return None


class _RecoveryCheckpointManager:
    def __init__(
        self, root: Path, run_id: str, recovered_context: dict[str, object] | None = None
    ) -> None:
        self.run_id = run_id
        self.checkpoint_dir = root / "checkpoints"
        self.checkpoint_dir.mkdir(parents=True, exist_ok=True)
        self._recovered_context = recovered_context
        self.outcomes: list[tuple[str, str]] = []

    def get_remaining_stages(self, all_stages: list[str]) -> list[str]:
        return list(all_stages)

    def load_latest_context_snapshot(self, _completed_stages: object) -> dict[str, object] | None:
        return self._recovered_context

    def mark_stage_outcome(self, stage_name: str, status: str, **_kwargs: object) -> None:
        self.outcomes.append((stage_name, status))

    def save_context_snapshot(self, stage_name: str, _snapshot: dict[str, object]) -> Path:
        snapshot_path = self.checkpoint_dir / f"{stage_name}.json"
        snapshot_path.write_text("{}", encoding="utf-8")
        return snapshot_path


def _make_config(tmp_path: Path) -> SimpleNamespace:
    return SimpleNamespace(
        target_name="example.com",
        output_dir=str(tmp_path / "output"),
        output={},
        tools={"subfinder": True},
        screenshots={},
        cache={},
        storage={},
    )


def _make_args(config: SimpleNamespace) -> argparse.Namespace:
    return argparse.Namespace(
        config="unused-config.json",
        scope="unused-scope.txt",
        dry_run=False,
        skip_crtsh=True,
        refresh_cache=False,
        force_fresh_run=False,
        _loaded_config=config,
        _loaded_scope_entries=["example.com"],
    )


def _patch_runtime_environment(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    emitted_progress: list[dict[str, object]],
) -> None:
    def _capture_progress(stage: str, message: str, percent: int, **meta: object) -> None:
        event: dict[str, object] = {"stage": stage, "message": message, "percent": int(percent)}
        event.update({str(k): v for k, v in meta.items()})
        emitted_progress.append(event)

    monkeypatch.setattr(orch_mod, "emit_progress", _capture_progress)
    monkeypatch.setattr(orch_mod, "emit_error", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(orch_mod, "pipeline_flow_manifest", lambda: [])
    monkeypatch.setattr(orch_mod, "build_tool_status", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(orch_mod, "cache_enabled", lambda *_args, **_kwargs: False)
    monkeypatch.setattr(orch_mod, "find_previous_run", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(orch_mod, "generate_run_id", lambda: "run-test")
    monkeypatch.setattr(orch_mod, "StageCheckpointGuard", _NoopCheckpointGuard)
    monkeypatch.setattr(
        orch_mod.PipelineOutputStore,
        "create",
        lambda *_args, **_kwargs: _DummyOutputStore(tmp_path),
    )
    monkeypatch.setattr(
        PipelineOrchestrator,
        "_record_stage_post_run",
        AsyncMock(return_value=None),
    )

    learning_module = ModuleType("src.learning.integration")
    learning_module.LearningIntegration = SimpleNamespace(
        get_or_create=lambda *_args, **_kwargs: _DummyLearning()
    )
    monkeypatch.setitem(sys.modules, "src.learning.integration", learning_module)


def test_stage_checkpoint_guard_preserves_explicit_failure_state(tmp_path: Path) -> None:
    manager = CheckpointManager(tmp_path / "checkpoints", "run-a")

    with StageCheckpointGuard(manager, "live_hosts"):
        manager.mark_stage_outcome(
            "live_hosts",
            "failed",
            error="probe timeout",
            result={"status": "failed", "error": "probe timeout"},
        )

    state = manager.load()
    assert state is not None
    assert state.stage_results["live_hosts"]["status"] == "failed"
    assert "live_hosts" not in set(state.completed_stages)


def test_checkpoint_manager_roundtrips_context_snapshot(tmp_path: Path) -> None:
    manager = CheckpointManager(tmp_path / "checkpoints", "run-context")
    snapshot = {
        "scope_entries": ["example.com"],
        "stage_status": {"subdomains": "COMPLETED"},
        "module_metrics": {"subdomains": {"status": "ok"}},
    }

    manager.save_context_snapshot("subdomains", snapshot)
    loaded = manager.load_latest_context_snapshot(["subdomains"])

    assert loaded == snapshot


@pytest.mark.asyncio
async def test_orchestrator_recovery_uses_context_snapshot_and_skips_completed_stages(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    emitted_progress: list[dict[str, object]] = []
    _patch_runtime_environment(monkeypatch, tmp_path, emitted_progress)
    monkeypatch.setattr(orch_mod, "STAGE_ORDER", ["subdomains", "live_hosts", "urls"])

    recovered_context: dict[str, object] = {
        "scope_entries": ["example.com"],
        "subdomains": ["a.example.com"],
        "live_hosts": ["https://a.example.com"],
        "stage_status": {
            "subdomains": "COMPLETED",
            "live_hosts": "COMPLETED",
        },
        "module_metrics": {
            "subdomains": {"status": "ok"},
            "live_hosts": {"status": "ok"},
        },
    }

    managers: dict[str, _RecoveryCheckpointManager] = {}

    def _create_checkpoint_manager(_output: Path, _target: str, run_id: str | None = None, **kwargs: object):
        key = str(run_id or "run-test")
        if key not in managers:
            managers[key] = _RecoveryCheckpointManager(
                tmp_path,
                key,
                recovered_context if key == "run-old" else None,
            )
        return managers[key]

    monkeypatch.setattr(orch_mod, "create_checkpoint_manager", _create_checkpoint_manager)
    monkeypatch.setattr(
        orch_mod,
        "attempt_recovery",
        lambda *_args, **_kwargs: (
            True,
            CheckpointState(
                pipeline_run_id="run-old",
                checkpoint_version=2,
                completed_stages=["subdomains", "live_hosts"],
            ),
        ),
    )

    subdomains_runner = AsyncMock(return_value=None)
    live_hosts_runner = AsyncMock(return_value=None)

    async def _urls_ok(_args: argparse.Namespace, _config: object, ctx: object) -> None:
        ctx.result.urls = {"https://a.example.com/path"}
        ctx.result.module_metrics["urls"] = {"status": "ok"}
        ctx.result.stage_status["urls"] = "COMPLETED"

    urls_runner = AsyncMock(side_effect=_urls_ok)

    monkeypatch.setattr(orch_mod, "run_subdomain_enumeration", subdomains_runner, raising=False)
    monkeypatch.setattr(orch_mod, "run_live_hosts", live_hosts_runner, raising=False)
    monkeypatch.setattr(orch_mod, "run_url_collection", urls_runner, raising=False)

    orchestrator = PipelineOrchestrator()
    exit_code = await orchestrator.run(_make_args(_make_config(tmp_path)))

    assert exit_code == 0
    assert subdomains_runner.await_count == 0
    assert live_hosts_runner.await_count == 0
    assert urls_runner.await_count == 1
    assert any(
        event.get("stage") == "startup"
        and "Recovered checkpoint run run-old" in str(event.get("message", ""))
        for event in emitted_progress
    )


@pytest.mark.asyncio
async def test_failed_stage_emits_stage_failed_summary_not_stage_complete(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    emitted_progress: list[dict[str, object]] = []
    _patch_runtime_environment(monkeypatch, tmp_path, emitted_progress)
    monkeypatch.setattr(orch_mod, "STAGE_ORDER", ["subdomains"])

    monkeypatch.setattr(
        orch_mod,
        "create_checkpoint_manager",
        lambda *_args, **_kwargs: _RecoveryCheckpointManager(tmp_path, "run-test"),
    )
    monkeypatch.setattr(orch_mod, "attempt_recovery", lambda *_args, **_kwargs: (False, None))

    async def _failed_stage(
        _args: argparse.Namespace,
        _config: object,
        ctx: object,
    ) -> None:
        ctx.result.module_metrics["subdomains"] = {
            "status": "failed",
            "failure_reason": "mock failure",
            "error": "mock failure",
        }
        ctx.result.stage_status["subdomains"] = "FAILED"
        ctx.result.urls = {"https://example.com"}

    monkeypatch.setattr(orch_mod, "run_subdomain_enumeration", _failed_stage, raising=False)

    orchestrator = PipelineOrchestrator()
    exit_code = await orchestrator.run(_make_args(_make_config(tmp_path)))

    assert exit_code == 1
    assert any(
        event.get("stage") == "subdomains"
        and event.get("event_trigger") == "stage_failed"
        and str(event.get("message", "")).startswith("Stage failed:")
        for event in emitted_progress
    )
    assert not any(
        event.get("stage") == "subdomains"
        and event.get("event_trigger") == "stage_complete"
        and event.get("status") == "error"
        for event in emitted_progress
    )
