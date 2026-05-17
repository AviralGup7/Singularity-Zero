import argparse
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock

import pytest

from src.core.events import EventBus, EventType, PipelineEvent
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


class _DummyCheckpointManager:
    def __init__(self, root: Path) -> None:
        self.checkpoint_dir = root / "checkpoints"
        self.checkpoint_dir.mkdir(parents=True, exist_ok=True)

    def get_remaining_stages(self, all_stages: list[str]) -> list[str]:
        return list(all_stages)


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


def _make_config(tmp_path: Path) -> SimpleNamespace:
    return SimpleNamespace(
        target_name="example.com",
        output_dir=tmp_path / "output",
        output={},
        tools={"subfinder": True},
        screenshots={},
        cache={},
        storage={},
    )


def _patch_runtime_environment(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(orch_mod, "emit_progress", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(orch_mod, "emit_error", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(orch_mod, "pipeline_flow_manifest", lambda: [])
    monkeypatch.setattr(orch_mod, "build_tool_status", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(orch_mod, "cache_enabled", lambda *_args, **_kwargs: False)
    monkeypatch.setattr(orch_mod, "find_previous_run", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(orch_mod, "generate_run_id", lambda: "run-events")
    monkeypatch.setattr(
        orch_mod,
        "create_checkpoint_manager",
        lambda *_args, **_kwargs: _DummyCheckpointManager(tmp_path),
    )
    monkeypatch.setattr(orch_mod, "attempt_recovery", lambda *_args, **_kwargs: (False, None))
    monkeypatch.setattr(orch_mod, "StageCheckpointGuard", _NoopCheckpointGuard)
    learning_module = ModuleType("src.learning.integration")
    learning_module.LearningIntegration = SimpleNamespace(
        get_or_create=lambda *_args, **_kwargs: _DummyLearning()
    )
    monkeypatch.setitem(sys.modules, "src.learning.integration", learning_module)
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


@pytest.mark.asyncio
async def test_orchestrator_emits_domain_events(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _patch_runtime_environment(monkeypatch, tmp_path)
    monkeypatch.setattr(orch_mod, "STAGE_ORDER", ["subdomains"])

    from src.core.contracts.pipeline_runtime import StageOutcome, StageOutput

    async def _successful_stage(*args: Any, **kwargs: Any) -> StageOutput:
        ctx = kwargs.get("ctx") or args[2]
        finding = {"title": "Example Finding", "severity": "low", "confidence": 0.9}
        ctx.result.reportable_findings = [finding]
        ctx.result.stage_status["subdomains"] = "COMPLETED"

        return StageOutput(
            stage_name="subdomains",
            outcome=StageOutcome.COMPLETED,
            duration_seconds=1.0,
            state_delta={"reportable_findings": [finding]},
        )

    from src.core.plugins import register_plugin
    from src.pipeline.services.plugin_catalog import RECON_PROVIDER, resolve_stage_runner

    try:
        resolve_stage_runner("subdomains")
    except Exception:  # noqa: S110
        pass

    register_plugin(RECON_PROVIDER, "subdomains")(_successful_stage)

    bus = EventBus()
    observed: list[PipelineEvent] = []

    def _capture(event: PipelineEvent) -> None:
        observed.append(event)

    for event_type in (
        EventType.PIPELINE_STARTED,
        EventType.STAGE_STARTED,
        EventType.FINDING_CREATED,
        EventType.STAGE_COMPLETED,
        EventType.PIPELINE_COMPLETE,
    ):
        bus.subscribe(event_type, _capture)

    orchestrator = PipelineOrchestrator(event_bus=bus)
    exit_code = await orchestrator.run(_make_args(_make_config(tmp_path)))

    assert exit_code == 0
    event_types = [event.event_type for event in observed]
    assert event_types[0] == EventType.PIPELINE_STARTED
    assert EventType.STAGE_STARTED in event_types
    assert EventType.FINDING_CREATED in event_types
    assert EventType.STAGE_COMPLETED in event_types
    assert event_types[-1] == EventType.PIPELINE_COMPLETE

    stage_started = next(event for event in observed if event.event_type == EventType.STAGE_STARTED)
    assert stage_started.data["contract"]["stage_name"] == "subdomains"

    stage_completed = next(
        event for event in observed if event.event_type == EventType.STAGE_COMPLETED
    )
    assert stage_completed.data["contract"]["outcome"] == "completed"
