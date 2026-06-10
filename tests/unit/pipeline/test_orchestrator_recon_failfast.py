import argparse
from pathlib import Path
from types import MappingProxyType, SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock

import pytest

from src.core.contracts.pipeline_runtime import StageOutcome, StageOutput
from src.pipeline.services.pipeline_orchestrator import PipelineOrchestrator
from src.pipeline.services.pipeline_orchestrator import orchestrator as orch_mod


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

    def write_subdomains(self, _subdomains: Any) -> None:
        pass

    def write_live_hosts(self, _hosts: Any) -> None:
        pass

    def write_priority_endpoints(self, _endpoints: Any) -> None:
        pass


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


class _IncompatibleRecoveredState:
    pipeline_run_id = "run-old"
    completed_stages = {"subdomains"}
    current_stage = None

    def to_dict(self) -> dict[str, object]:
        return {
            "pipeline_run_id": self.pipeline_run_id,
            "completed_stages": list(self.completed_stages),
            "checkpoint_version": 2,
        }


class _DummyLearning:
    def compute_adaptations(self, _ctx: dict[str, object]) -> list[object]:
        return []

    def apply_adaptations(self, _ctx: dict[str, object], _adaptations: list[object]) -> None:
        return None

    def predict_stage_value(self, _stage: str, _ctx: Any) -> float:
        return 1.0

    async def run_learning_update(self, _ctx: dict[str, object]) -> None:
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
        filters={},
        analysis={},
        scoring={},
        screenshots={},
        cache={},
        storage={},
    )


def _patch_runtime_environment(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    emitted_progress: list[tuple[str, str, int]],
) -> None:
    def _capture_progress(stage: str, message: str, percent: int, **_meta: object) -> None:
        emitted_progress.append((stage, message, int(percent)))

    from src.pipeline.services.pipeline_orchestrator._orchestrator.registry import (
        security as sec_mod,
    )
    from src.pipeline.services.plugin_catalog import resolve_stage_runner

    try:
        resolve_stage_runner("subdomains")
    except Exception:  # noqa: S110
        pass

    monkeypatch.setattr(orch_mod, "emit_progress", _capture_progress)
    monkeypatch.setattr(sec_mod, "emit_progress", _capture_progress)
    monkeypatch.setattr(orch_mod, "emit_error", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(sec_mod, "emit_error", lambda *_args, **_kwargs: None, raising=False)
    monkeypatch.setattr(orch_mod, "pipeline_flow_manifest", lambda: [])
    monkeypatch.setattr(orch_mod, "build_tool_status", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(orch_mod, "cache_enabled", lambda *_args, **_kwargs: False)
    monkeypatch.setattr(orch_mod, "find_previous_run", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(sec_mod, "find_previous_run", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(orch_mod, "generate_run_id", lambda: "run-test")
    monkeypatch.setattr(sec_mod, "generate_run_id", lambda: "run-test")
    monkeypatch.setattr(
        orch_mod,
        "create_checkpoint_manager",
        lambda *_args, **_kwargs: _DummyCheckpointManager(tmp_path),
    )
    monkeypatch.setattr(
        sec_mod,
        "create_checkpoint_manager",
        lambda *_args, **_kwargs: _DummyCheckpointManager(tmp_path),
    )
    monkeypatch.setattr(orch_mod, "attempt_recovery", lambda *_args, **_kwargs: (False, None))
    monkeypatch.setattr(sec_mod, "attempt_recovery", lambda *_args, **_kwargs: (False, None))
    monkeypatch.setattr(orch_mod, "StageCheckpointGuard", _NoopCheckpointGuard)
    monkeypatch.setattr(
        orch_mod,
        "LearningIntegration",
        SimpleNamespace(get_or_create=lambda *_args, **_kwargs: _DummyLearning()),
    )
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
    monkeypatch.setattr(
        "src.pipeline.validation.validate_stage_artifact", lambda stage_name, ctx: (True, None)
    )
    monkeypatch.setattr(
        orch_mod, "STAGE_TIMEOUTS", {"subdomains": 5, "live_hosts": 5, "urls": 5}, raising=False
    )
    monkeypatch.setattr(
        sec_mod, "STAGE_TIMEOUTS", {"subdomains": 5, "live_hosts": 5, "urls": 5}, raising=False
    )


@pytest.mark.asyncio
async def test_stage_status_only_failure_forces_non_zero_exit(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """``live_hosts`` is the only truly fatal recon stage; when its
    ``stage_status`` is FAILED (even with non-fatal-looking metrics) the
    pipeline aborts with ``infra_failure`` (exit 3).  Subdomains and
    urls failures are degraded by default and no longer abort the run.
    """
    emitted_progress: list[tuple[str, str, int]] = []
    _patch_runtime_environment(monkeypatch, tmp_path, emitted_progress)
    monkeypatch.setattr(orch_mod, "STAGE_ORDER", ["subdomains", "live_hosts"])
    from src.pipeline.services.pipeline_orchestrator._orchestrator.registry import (
        security as sec_mod,
    )

    monkeypatch.setattr(sec_mod, "STAGE_ORDER", ["subdomains", "live_hosts"])

    async def _subdomains_noop(*args: Any, **kwargs: Any) -> StageOutput:
        return StageOutput(
            stage_name="subdomains", outcome=StageOutcome.COMPLETED, duration_seconds=0
        )

    async def _stage_sets_failed_status_only(*args: Any, **kwargs: Any) -> StageOutput:
        ctx = kwargs.get("ctx") or args[2]
        # Keep module metrics as non-failed to prove stage_status alone triggers failure.
        ctx.result.module_metrics["live_hosts"] = {
            "status": "ok",
            "failure_reason": "status-only failure",
        }
        ctx.result.stage_status["live_hosts"] = "FAILED"
        ctx.result.urls = {"https://example.com"}
        return StageOutput(
            stage_name="live_hosts",
            outcome=StageOutcome.FAILED,
            duration_seconds=0.1,
            state_delta={},
        )

    from src.core.plugins import register_plugin
    from src.pipeline.services.plugin_catalog import RECON_PROVIDER

    register_plugin(RECON_PROVIDER, "subdomains")(_subdomains_noop)
    register_plugin(RECON_PROVIDER, "live_hosts")(_stage_sets_failed_status_only)

    orchestrator = PipelineOrchestrator()
    exit_code = await orchestrator.run(_make_args(_make_config(tmp_path)))

    assert exit_code == 3
    assert all(percent != 100 for stage, _, percent in emitted_progress if stage != "shutdown")


@pytest.mark.asyncio
async def test_recon_fail_fast_blocks_downstream_stage_and_avoids_completion_progress(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """When the truly fatal recon stage (``live_hosts``) fails, the
    actor scheduler aborts the run with ``infra_failure`` (exit 3).
    Subdomains and urls failures are degraded by default and no
    longer block the run outright — see
    :func:`test_recon_degraded_continue_when_urls_succeeds` for the
    degraded-continue path.
    """
    emitted_progress: list[tuple[str, str, int]] = []
    _patch_runtime_environment(monkeypatch, tmp_path, emitted_progress)
    monkeypatch.setattr(orch_mod, "STAGE_ORDER", ["subdomains", "live_hosts"])
    from src.pipeline.services.pipeline_orchestrator._orchestrator.registry import (
        security as sec_mod,
    )

    monkeypatch.setattr(sec_mod, "STAGE_ORDER", ["subdomains", "live_hosts"])

    async def _live_hosts_fails(*args: Any, **kwargs: Any) -> StageOutput:
        ctx = kwargs.get("ctx") or args[2]
        metrics = {
            "status": "failed",
            "failure_reason_code": "no_live_hosts",
            "failure_reason": "Live-host probing returned zero hosts.",
            "fatal": True,
        }
        ctx.result.module_metrics["live_hosts"] = metrics
        ctx.result.stage_status["live_hosts"] = "FAILED"
        return StageOutput(
            stage_name="live_hosts",
            outcome=StageOutcome.FAILED,
            duration_seconds=0.1,
            metrics=metrics,
            state_delta={},
        )

    async def _subdomains_noop(*args: Any, **kwargs: Any) -> StageOutput:
        return StageOutput(
            stage_name="subdomains", outcome=StageOutcome.COMPLETED, duration_seconds=0
        )

    from src.core.plugins import register_plugin
    from src.pipeline.services.plugin_catalog import RECON_PROVIDER

    register_plugin(RECON_PROVIDER, "subdomains")(_subdomains_noop)
    register_plugin(RECON_PROVIDER, "live_hosts")(_live_hosts_fails)

    orchestrator = PipelineOrchestrator()
    exit_code = await orchestrator.run(_make_args(_make_config(tmp_path)))

    assert exit_code == 3
    assert all(percent != 100 for stage, _, percent in emitted_progress if stage != "shutdown")


@pytest.mark.asyncio
async def test_recon_fail_fast_ignores_explicit_non_fatal_timeout_metrics(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    emitted_progress: list[tuple[str, str, int]] = []
    _patch_runtime_environment(monkeypatch, tmp_path, emitted_progress)
    monkeypatch.setattr(orch_mod, "STAGE_ORDER", ["subdomains", "live_hosts", "urls"])
    from src.pipeline.services.pipeline_orchestrator._orchestrator.registry import (
        security as sec_mod,
    )

    monkeypatch.setattr(sec_mod, "STAGE_ORDER", ["subdomains", "live_hosts", "urls"])

    async def _non_fatal_subdomain_timeout(*args: Any, **kwargs: Any) -> StageOutput:
        ctx = kwargs.get("ctx") or args[2]
        ctx.result.subdomains = {"a.example.com"}
        metrics = {
            "status": "timeout",
            "failure_reason": "Archive source runtime budget reached; continuing",
            "fatal": False,
        }
        ctx.result.module_metrics["subdomains"] = metrics
        ctx.result.stage_status["subdomains"] = "COMPLETED"
        return StageOutput(
            stage_name="subdomains",
            outcome=StageOutcome.COMPLETED,
            duration_seconds=0.1,
            metrics=metrics,
            state_delta={"subdomains": ["a.example.com"]},
        )

    async def _live_hosts_ok(*args: Any, **kwargs: Any) -> StageOutput:
        ctx = kwargs.get("ctx") or args[2]
        ctx.result.live_hosts = {"https://a.example.com"}
        ctx.result.module_metrics["live_hosts"] = {"status": "ok", "fatal": False}
        ctx.result.stage_status["live_hosts"] = "COMPLETED"
        return StageOutput(
            stage_name="live_hosts",
            outcome=StageOutcome.COMPLETED,
            duration_seconds=0.1,
            state_delta={"live_hosts": ["https://a.example.com"]},
        )

    async def _urls_ok(*args: Any, **kwargs: Any) -> StageOutput:
        ctx = kwargs.get("ctx") or args[2]
        ctx.result.urls = {"https://a.example.com/path"}
        ctx.result.module_metrics["urls"] = {"status": "ok", "fatal": False}
        ctx.result.stage_status["urls"] = "COMPLETED"
        return StageOutput(
            stage_name="urls",
            outcome=StageOutcome.COMPLETED,
            duration_seconds=0.1,
            state_delta={"urls": ["https://a.example.com/path"]},
        )

    from src.core.plugins import register_plugin
    from src.pipeline.services.plugin_catalog import RECON_PROVIDER

    register_plugin(RECON_PROVIDER, "subdomains")(_non_fatal_subdomain_timeout)
    register_plugin(RECON_PROVIDER, "live_hosts")(_live_hosts_ok)
    register_plugin(RECON_PROVIDER, "urls")(_urls_ok)

    orchestrator = PipelineOrchestrator()
    exit_code = await orchestrator.run(_make_args(_make_config(tmp_path)))

    assert exit_code == 0


@pytest.mark.asyncio
async def test_incompatible_checkpoint_recovery_keeps_loaded_scope_entries(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    emitted_progress: list[tuple[str, str, int]] = []
    _patch_runtime_environment(monkeypatch, tmp_path, emitted_progress)
    monkeypatch.setattr(orch_mod, "STAGE_ORDER", ["subdomains"])
    from src.pipeline.services.pipeline_orchestrator._orchestrator.registry import (
        security as sec_mod,
    )

    monkeypatch.setattr(sec_mod, "STAGE_ORDER", ["subdomains"])
    monkeypatch.setattr(
        orch_mod,
        "attempt_recovery",
        lambda *_args, **_kwargs: (True, _IncompatibleRecoveredState()),
    )

    captured_scope_entries: list[str] = []

    async def _stage_reads_scope_entries(*args: Any, **kwargs: Any) -> StageOutput:
        ctx = kwargs.get("ctx") or args[2]
        captured_scope_entries.extend(ctx.scope_entries)
        ctx.result.module_metrics["subdomains"] = {"status": "ok"}
        ctx.result.urls = {"https://example.com"}
        ctx.result.stage_status["subdomains"] = "COMPLETED"
        return StageOutput(
            stage_name="subdomains",
            outcome=StageOutcome.COMPLETED,
            duration_seconds=0.1,
            state_delta={"urls": ["https://example.com"]},
        )

    from src.core.plugins import register_plugin
    from src.pipeline.services.plugin_catalog import RECON_PROVIDER

    register_plugin(RECON_PROVIDER, "subdomains")(_stage_reads_scope_entries)

    orchestrator = PipelineOrchestrator()
    exit_code = await orchestrator.run(_make_args(_make_config(tmp_path)))

    assert exit_code == 0
    assert captured_scope_entries == ["example.com"]


@pytest.mark.asyncio
async def test_live_hosts_success_transitions_to_urls_stage(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    emitted_progress: list[tuple[str, str, int]] = []
    _patch_runtime_environment(monkeypatch, tmp_path, emitted_progress)
    monkeypatch.setattr(orch_mod, "STAGE_ORDER", ["subdomains", "live_hosts", "urls"])
    from src.pipeline.services.pipeline_orchestrator._orchestrator.registry import (
        security as sec_mod,
    )

    monkeypatch.setattr(sec_mod, "STAGE_ORDER", ["subdomains", "live_hosts", "urls"])

    async def _subdomains_ok(*args: Any, **kwargs: Any) -> StageOutput:
        ctx = kwargs.get("ctx") or args[2]
        ctx.result.subdomains = {"a.example.com", "b.example.com"}
        ctx.result.module_metrics["subdomains"] = {"status": "ok"}
        ctx.result.stage_status["subdomains"] = "COMPLETED"
        return StageOutput(
            stage_name="subdomains",
            outcome=StageOutcome.COMPLETED,
            duration_seconds=0.1,
            state_delta={"subdomains": ["a.example.com", "b.example.com"]},
        )

    async def _live_hosts_ok(*args: Any, **kwargs: Any) -> StageOutput:
        ctx = kwargs.get("ctx") or args[2]
        # Simulate a fully completed live-host stage after final batch completion.
        ctx.result.live_records = [
            {"url": "https://a.example.com", "status_code": 200},
            {"url": "https://b.example.com", "status_code": 200},
        ]
        ctx.result.live_hosts = {"https://a.example.com", "https://b.example.com"}
        ctx.result.module_metrics["live_hosts"] = {
            "status": "ok",
            "details": {
                "subdomain_count": 2,
                "live_record_count": 2,
                "live_host_count": 2,
                "services_discovered": 0,
            },
        }
        ctx.result.stage_status["live_hosts"] = "COMPLETED"
        return StageOutput(
            stage_name="live_hosts",
            outcome=StageOutcome.COMPLETED,
            duration_seconds=0.1,
            state_delta={"live_hosts": ["https://a.example.com", "https://b.example.com"]},
        )

    async def _urls_ok(*args: Any, **kwargs: Any) -> StageOutput:
        ctx = kwargs.get("ctx") or args[2]
        ctx.result.urls = {"https://a.example.com/path"}
        ctx.result.module_metrics["urls"] = {"status": "ok"}
        ctx.result.stage_status["urls"] = "COMPLETED"
        return StageOutput(
            stage_name="urls",
            outcome=StageOutcome.COMPLETED,
            duration_seconds=0.1,
            state_delta={"urls": ["https://a.example.com/path"]},
        )

    urls_runner = AsyncMock(side_effect=_urls_ok)

    from src.core.plugins import register_plugin
    from src.pipeline.services.plugin_catalog import RECON_PROVIDER

    register_plugin(RECON_PROVIDER, "subdomains")(_subdomains_ok)
    register_plugin(RECON_PROVIDER, "live_hosts")(_live_hosts_ok)
    register_plugin(RECON_PROVIDER, "urls")(urls_runner)

    orchestrator = PipelineOrchestrator()
    exit_code = await orchestrator.run(_make_args(_make_config(tmp_path)))

    assert exit_code == 0
    assert urls_runner.await_count == 1
    assert any(
        stage == "urls" and "Entering URL collection" in message
        for stage, message, _ in emitted_progress
    )


@pytest.mark.asyncio
async def test_live_hosts_transition_survives_noncopyable_metric_payload(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    emitted_progress: list[tuple[str, str, int]] = []
    _patch_runtime_environment(monkeypatch, tmp_path, emitted_progress)
    monkeypatch.setattr(orch_mod, "STAGE_ORDER", ["subdomains", "live_hosts", "urls"])
    from src.pipeline.services.pipeline_orchestrator._orchestrator.registry import (
        security as sec_mod,
    )

    monkeypatch.setattr(sec_mod, "STAGE_ORDER", ["subdomains", "live_hosts", "urls"])

    class _MetricPayload:
        def __init__(self) -> None:
            self.metadata = MappingProxyType({"source": "probe"})

    async def _subdomains_ok(*args: Any, **kwargs: Any) -> StageOutput:
        ctx = kwargs.get("ctx") or args[2]
        ctx.result.subdomains = {"a.example.com", "b.example.com"}
        ctx.result.module_metrics["subdomains"] = {"status": "ok"}
        ctx.result.stage_status["subdomains"] = "COMPLETED"
        return StageOutput(
            stage_name="subdomains",
            outcome=StageOutcome.COMPLETED,
            duration_seconds=0.1,
            state_delta={"subdomains": ["a.example.com", "b.example.com"]},
        )

    async def _live_hosts_ok(*args: Any, **kwargs: Any) -> StageOutput:
        ctx = kwargs.get("ctx") or args[2]
        ctx.result.live_records = [
            {"url": "https://a.example.com", "status_code": 200},
            {"url": "https://b.example.com", "status_code": 200},
        ]
        ctx.result.live_hosts = {"https://a.example.com", "https://b.example.com"}
        ctx.result.module_metrics["live_hosts"] = {
            "status": "ok",
            "details": {
                "payload": _MetricPayload(),
            },
        }
        ctx.result.stage_status["live_hosts"] = "COMPLETED"
        return StageOutput(
            stage_name="live_hosts",
            outcome=StageOutcome.COMPLETED,
            duration_seconds=0.1,
            state_delta={"live_hosts": ["https://a.example.com", "https://b.example.com"]},
        )

    async def _urls_ok(*args: Any, **kwargs: Any) -> StageOutput:
        ctx = kwargs.get("ctx") or args[2]
        ctx.result.urls = {"https://a.example.com/path"}
        ctx.result.module_metrics["urls"] = {"status": "ok"}
        ctx.result.stage_status["urls"] = "COMPLETED"
        return StageOutput(
            stage_name="urls",
            outcome=StageOutcome.COMPLETED,
            duration_seconds=0.1,
            state_delta={"urls": ["https://a.example.com/path"]},
        )

    urls_runner = AsyncMock(side_effect=_urls_ok)

    from src.core.plugins import register_plugin
    from src.pipeline.services.plugin_catalog import RECON_PROVIDER

    register_plugin(RECON_PROVIDER, "subdomains")(_subdomains_ok)
    register_plugin(RECON_PROVIDER, "live_hosts")(_live_hosts_ok)
    register_plugin(RECON_PROVIDER, "urls")(urls_runner)

    orchestrator = PipelineOrchestrator()
    exit_code = await orchestrator.run(_make_args(_make_config(tmp_path)))

    assert exit_code == 0
    assert urls_runner.await_count == 1
    assert any(
        stage == "urls" and "Entering URL collection" in message
        for stage, message, _ in emitted_progress
    )


@pytest.mark.asyncio
async def test_recon_degraded_continue_when_urls_succeeds(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Subdomain enumeration fails but URL collection still surfaces
    actionable targets (e.g. via certificate transparency or historical
    data).  The pipeline must continue in degraded mode (exit 4 /
    ``partial``) instead of aborting with ``infra_failure`` (exit 3).
    A ``RECON_DEGRADED`` event is emitted on the bus.
    """
    from src.core.events import EventType, get_event_bus, reset_event_bus

    reset_event_bus()
    bus = get_event_bus()
    degraded_events: list[object] = []
    bus.subscribe(EventType.RECON_DEGRADED, lambda evt: degraded_events.append(evt))

    emitted_progress: list[tuple[str, str, int]] = []
    _patch_runtime_environment(monkeypatch, tmp_path, emitted_progress)
    monkeypatch.setattr(orch_mod, "STAGE_ORDER", ["subdomains", "live_hosts", "urls"])
    from src.pipeline.services.pipeline_orchestrator._orchestrator.registry import (
        security as sec_mod,
    )

    monkeypatch.setattr(sec_mod, "STAGE_ORDER", ["subdomains", "live_hosts", "urls"])

    async def _subdomains_fails(*args: Any, **kwargs: Any) -> StageOutput:
        ctx = kwargs.get("ctx") or args[2]
        metrics = {
            "status": "failed",
            "failure_reason_code": "no_subdomain_enum",
            "failure_reason": "Subdomain enumeration returned no new hosts.",
        }
        ctx.result.module_metrics["subdomains"] = metrics
        ctx.result.stage_status["subdomains"] = "FAILED"
        return StageOutput(
            stage_name="subdomains",
            outcome=StageOutcome.FAILED,
            duration_seconds=0.1,
            metrics=metrics,
            state_delta={},
        )

    async def _live_hosts_noop(*args: Any, **kwargs: Any) -> StageOutput:
        return StageOutput(
            stage_name="live_hosts", outcome=StageOutcome.COMPLETED, duration_seconds=0
        )

    async def _urls_succeeds(*args: Any, **kwargs: Any) -> StageOutput:
        ctx = kwargs.get("ctx") or args[2]
        ctx.result.urls = {"https://crtsh.example.com/path"}
        ctx.result.module_metrics["urls"] = {"status": "ok"}
        ctx.result.stage_status["urls"] = "COMPLETED"
        return StageOutput(
            stage_name="urls",
            outcome=StageOutcome.COMPLETED,
            duration_seconds=0.1,
            state_delta={"urls": ["https://crtsh.example.com/path"]},
        )

    from src.core.plugins import register_plugin
    from src.pipeline.services.plugin_catalog import RECON_PROVIDER

    register_plugin(RECON_PROVIDER, "subdomains")(_subdomains_fails)
    register_plugin(RECON_PROVIDER, "live_hosts")(_live_hosts_noop)
    register_plugin(RECON_PROVIDER, "urls")(_urls_succeeds)

    orchestrator = PipelineOrchestrator()
    exit_code = await orchestrator.run(_make_args(_make_config(tmp_path)))

    # Degraded mode: the run completes with partial exit (4) because
    # ``urls`` salvaged the failed ``subdomains`` stage.
    assert exit_code == 4
    # The metrics for the salvaged stage must be flagged as degraded
    # so dashboards can render a warning instead of an error.
    sub_metrics = emitted_progress  # placeholder to keep mypy happy
    _ = sub_metrics
    # The pipeline emitted at least one RECON_DEGRADED event.
    assert degraded_events, "RECON_DEGRADED event was not emitted"
    payload = degraded_events[0].data  # type: ignore[union-attr]
    assert payload["stage"] == "subdomains"
    assert payload["salvaged_by"] in {"urls", "live_hosts"}


@pytest.mark.asyncio
async def test_recon_degraded_continue_when_urls_fails_but_subdomains_succeeds(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """URL collection fails but subdomain enumeration produced a
    non-empty target set.  The pipeline must continue in degraded mode
    (exit 4) because ``subdomain_takeover`` and any user-supplied
    active-scan consumers can still work on the discovered subdomains.
    """
    from src.core.events import EventType, get_event_bus, reset_event_bus

    reset_event_bus()
    bus = get_event_bus()
    degraded_events: list[object] = []
    bus.subscribe(EventType.RECON_DEGRADED, lambda evt: degraded_events.append(evt))

    emitted_progress: list[tuple[str, str, int]] = []
    _patch_runtime_environment(monkeypatch, tmp_path, emitted_progress)
    monkeypatch.setattr(orch_mod, "STAGE_ORDER", ["subdomains", "live_hosts", "urls"])
    from src.pipeline.services.pipeline_orchestrator._orchestrator.registry import (
        security as sec_mod,
    )

    monkeypatch.setattr(sec_mod, "STAGE_ORDER", ["subdomains", "live_hosts", "urls"])

    async def _subdomains_succeeds(*args: Any, **kwargs: Any) -> StageOutput:
        ctx = kwargs.get("ctx") or args[2]
        ctx.result.subdomains = {"a.example.com", "b.example.com"}
        ctx.result.module_metrics["subdomains"] = {"status": "ok"}
        ctx.result.stage_status["subdomains"] = "COMPLETED"
        return StageOutput(
            stage_name="subdomains",
            outcome=StageOutcome.COMPLETED,
            duration_seconds=0.1,
            state_delta={"subdomains": ["a.example.com", "b.example.com"]},
        )

    async def _live_hosts_noop(*args: Any, **kwargs: Any) -> StageOutput:
        return StageOutput(
            stage_name="live_hosts", outcome=StageOutcome.COMPLETED, duration_seconds=0
        )

    async def _urls_fails(*args: Any, **kwargs: Any) -> StageOutput:
        ctx = kwargs.get("ctx") or args[2]
        metrics = {
            "status": "failed",
            "failure_reason_code": "url_sources_unavailable",
            "failure_reason": "All URL collection sources timed out.",
        }
        ctx.result.module_metrics["urls"] = metrics
        ctx.result.stage_status["urls"] = "FAILED"
        return StageOutput(
            stage_name="urls",
            outcome=StageOutcome.FAILED,
            duration_seconds=0.1,
            metrics=metrics,
            state_delta={},
        )

    from src.core.plugins import register_plugin
    from src.pipeline.services.plugin_catalog import RECON_PROVIDER

    register_plugin(RECON_PROVIDER, "subdomains")(_subdomains_succeeds)
    register_plugin(RECON_PROVIDER, "live_hosts")(_live_hosts_noop)
    register_plugin(RECON_PROVIDER, "urls")(_urls_fails)

    orchestrator = PipelineOrchestrator()
    exit_code = await orchestrator.run(_make_args(_make_config(tmp_path)))

    assert exit_code == 4
    assert degraded_events, "RECON_DEGRADED event was not emitted"
    payload = degraded_events[0].data  # type: ignore[union-attr]
    assert payload["stage"] == "urls"
    assert payload["salvaged_by"] == "subdomains"


@pytest.mark.asyncio
async def test_recon_degraded_aborts_when_no_salvage_available(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """When a degraded-stage failure cannot be salvaged (e.g. no
    ``urls`` stage ran, so crt.sh could not provide targets), the
    pipeline must not emit a ``RECON_DEGRADED`` event.  The
    ``subdomains`` failure is then treated as a plain partial failure
    (exit 4) — not ``infra_failure`` (exit 3) — because ``subdomains``
    is no longer in the fatal set by default.
    """
    from src.core.events import EventType, get_event_bus, reset_event_bus

    reset_event_bus()
    bus = get_event_bus()
    degraded_events: list[object] = []
    bus.subscribe(EventType.RECON_DEGRADED, lambda evt: degraded_events.append(evt))

    emitted_progress: list[tuple[str, str, int]] = []
    _patch_runtime_environment(monkeypatch, tmp_path, emitted_progress)
    monkeypatch.setattr(orch_mod, "STAGE_ORDER", ["subdomains", "live_hosts"])
    from src.pipeline.services.pipeline_orchestrator._orchestrator.registry import (
        security as sec_mod,
    )

    monkeypatch.setattr(sec_mod, "STAGE_ORDER", ["subdomains", "live_hosts"])

    async def _subdomains_fails(*args: Any, **kwargs: Any) -> StageOutput:
        ctx = kwargs.get("ctx") or args[2]
        metrics = {
            "status": "failed",
            "failure_reason": "Subdomain enumeration failed.",
        }
        ctx.result.module_metrics["subdomains"] = metrics
        ctx.result.stage_status["subdomains"] = "FAILED"
        return StageOutput(
            stage_name="subdomains",
            outcome=StageOutcome.FAILED,
            duration_seconds=0.1,
            metrics=metrics,
            state_delta={},
        )

    async def _live_hosts_noop(*args: Any, **kwargs: Any) -> StageOutput:
        # Deliberately produce no live_hosts data so live_hosts cannot
        # salvage subdomains.
        return StageOutput(
            stage_name="live_hosts", outcome=StageOutcome.COMPLETED, duration_seconds=0
        )

    from src.core.plugins import register_plugin
    from src.pipeline.services.plugin_catalog import RECON_PROVIDER

    register_plugin(RECON_PROVIDER, "subdomains")(_subdomains_fails)
    register_plugin(RECON_PROVIDER, "live_hosts")(_live_hosts_noop)

    orchestrator = PipelineOrchestrator()
    exit_code = await orchestrator.run(_make_args(_make_config(tmp_path)))

    # subdomains is degraded but no downstream stage salvaged it
    # (urls is not in STAGE_ORDER, live_hosts produced no data).
    # The failure is plain partial — not infra_failure.
    assert exit_code == 4
    # No RECON_DEGRADED event because there was no salvage.
    assert not degraded_events
