import argparse
from pathlib import Path
from types import SimpleNamespace
from typing import Any
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

    async def run_learning_update(self, _ctx: dict[str, object]) -> None:
        return None

    def predict_stage_value(self, _stage: str, _ctx: Any) -> float:
        return 1.0



class _RecoveryCheckpointManager:
    def __init__(
        self, root: Path, run_id: str, recovered_context: dict[str, object] | None = None
    ) -> None:
        self.run_id = run_id
        self.checkpoint_dir = root / "checkpoints"
        self.checkpoint_dir.mkdir(parents=True, exist_ok=True)
        self._recovered_context = recovered_context
        self.outcomes: list[tuple[str, str]] = []
        self.completed_stages: list[str] = []
        if recovered_context and isinstance(recovered_context.get("stage_status"), dict):
            self.completed_stages = [
                k for k, v in recovered_context["stage_status"].items() if str(v).upper() == "COMPLETED"
            ]


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
        output_dir=tmp_path / "output",
        output={},
        tools={"subfinder": True},
        filters={},
        analysis={},
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
    from src.pipeline.services.pipeline_orchestrator._orchestrator.registry import (
        security as security_mod,
    )

    monkeypatch.setattr(security_mod, "emit_progress", _capture_progress)
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
    monkeypatch.setattr("src.pipeline.validation.validate_stage_artifact", lambda stage_name, ctx: (True, None))


    monkeypatch.setattr(
        orch_mod,
        "LearningIntegration",
        SimpleNamespace(get_or_create=lambda *_args, **_kwargs: _DummyLearning()),
    )


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
    _recovered_context = {
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
        "target_name": "example.com",
        "checkpoint_version": 2,
    }

    reduced_stages = ["subdomains", "live_hosts", "urls"]
    monkeypatch.setattr(orch_mod, "STAGE_ORDER", reduced_stages)

    from src.pipeline.services.pipeline_orchestrator import _constants as const_mod

    monkeypatch.setattr(const_mod, "STAGE_ORDER", reduced_stages)

    import src.pipeline.services.pipeline_orchestrator._orchestrator.security as security_mod

    monkeypatch.setattr(security_mod, "STAGE_ORDER", reduced_stages)

    def _create_checkpoint_manager(
        _output: Path, _target: str, run_id: str | None = None, **kwargs: object
    ):
        key = str(run_id or "run-test")
        if key == "run-old":
            return _RecoveryCheckpointManager(
                _output.parent / "run-old",
                key,
                _recovered_context,
            )
        return _RecoveryCheckpointManager(
            _output.parent / (key or "run-test"),
            key,
            None,
        )

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

    import src.pipeline.services.pipeline_orchestrator._orchestrator.security as security_mod

    monkeypatch.setattr(security_mod, "create_checkpoint_manager", _create_checkpoint_manager)
    monkeypatch.setattr(
        security_mod,
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

    async def _urls_ok(*args: Any, **kwargs: Any) -> None:
        ctx = kwargs.get("ctx") or args[2]
        ctx.result.urls = {"https://a.example.com/path"}
        ctx.result.module_metrics["urls"] = {"status": "ok"}
        ctx.result.stage_status["urls"] = "COMPLETED"

    urls_runner = AsyncMock(side_effect=_urls_ok)

    from src.core.plugins import register_plugin
    from src.pipeline.services.plugin_catalog import RECON_PROVIDER, resolve_stage_runner

    try:
        resolve_stage_runner("subdomains")
    except Exception:  # noqa: S110
        pass

    register_plugin(RECON_PROVIDER, "subdomains")(subdomains_runner)
    register_plugin(RECON_PROVIDER, "live_hosts")(live_hosts_runner)
    register_plugin(RECON_PROVIDER, "urls")(urls_runner)

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
    # ``live_hosts`` is the only truly fatal recon stage under the
    # default policy.  Use it here to exercise the
    # ``stage_failed`` progress event emission and the
    # ``infra_failure`` (exit 3) exit code path.
    monkeypatch.setattr(orch_mod, "STAGE_ORDER", ["subdomains", "live_hosts"])

    monkeypatch.setattr(
        orch_mod,
        "create_checkpoint_manager",
        lambda *_args, **_kwargs: _RecoveryCheckpointManager(tmp_path, "run-test"),
    )
    monkeypatch.setattr(orch_mod, "attempt_recovery", lambda *_args, **_kwargs: (False, None))

    async def _subdomains_noop(*args: Any, **kwargs: Any) -> None:
        return None

    async def _failed_stage(*args: Any, **kwargs: Any) -> None:
        ctx = kwargs.get("ctx") or args[2]
        ctx.result.module_metrics["live_hosts"] = {
            "status": "failed",
            "failure_reason": "mock failure",
            "error": "mock failure",
        }
        ctx.result.stage_status["live_hosts"] = "FAILED"
        ctx.result.urls = {"https://example.com"}

    from src.core.plugins import register_plugin
    from src.pipeline.services.plugin_catalog import RECON_PROVIDER, resolve_stage_runner

    try:
        resolve_stage_runner("subdomains")
    except Exception:  # noqa: S110
        pass

    register_plugin(RECON_PROVIDER, "subdomains")(_subdomains_noop)
    register_plugin(RECON_PROVIDER, "live_hosts")(_failed_stage)

    orchestrator = PipelineOrchestrator()
    exit_code = await orchestrator.run(_make_args(_make_config(tmp_path)))

    assert exit_code == 3
    assert any(
        event.get("stage") == "live_hosts"
        and event.get("event_trigger") == "stage_failed"
        and str(event.get("message", "")).startswith("Stage failed:")
        for event in emitted_progress
    )
    assert not any(
        event.get("stage") == "live_hosts"
        and event.get("event_trigger") == "stage_complete"
        and event.get("status") == "error"
        for event in emitted_progress
    )


def test_checkpoint_migration_v1_to_v2() -> None:
    from src.core.checkpoint.migrations import GLOBAL_MIGRATION_REGISTRY

    # Pre-migration v1 checkpoint data
    v1_data = {
        "pipeline_run_id": "test-run",
        "checkpoint_version": 1,
        # schema_version is missing (defaults to 1)
        "stage_results": {
            "active_scan": {
                "status": "completed",
                "reportable_findings": [
                    {
                        "category": "XSS",
                        # missing fields like title, url, severity, score, evidence, signals, cwe_id
                    }
                ]
            }
        }
    }

    migrated = GLOBAL_MIGRATION_REGISTRY.migrate(v1_data)
    assert migrated["schema_version"] == 2

    findings = migrated["stage_results"]["active_scan"]["reportable_findings"]
    assert len(findings) == 1
    f = findings[0]
    assert f["category"] == "XSS"
    assert f["title"] == ""
    assert f["url"] == ""
    assert f["severity"] == "low"
    assert f["confidence"] == 0.5
    assert f["score"] == 0
    assert f["evidence"] == {}
    assert f["signals"] == []
    assert f["cwe_id"] is None


def test_scope_merge_diffing_on_resume() -> None:
    from src.core.models.stage_result import PipelineContext, StageResult
    from src.pipeline.services.pipeline_orchestrator._orchestrator.security import (
        _merge_and_diff_scopes,
    )

    ctx = PipelineContext(
        result=StageResult(
            scope_entries=["example.com", "target.com"],
            subdomains={"a.example.com", "b.target.com", "other.com"},
            urls={"https://a.example.com/path", "https://b.target.com/path"},
            reportable_findings=[
                {"url": "https://a.example.com/path", "category": "vuln"},
                {"url": "https://other.com/path", "category": "vuln"},
            ]
        )
    )

    completed_stages = {"subdomains", "live_hosts", "urls"}

    # Current scope removes target.com and other.com, but adds new.com
    current_scope = ["example.com", "new.com"]

    _merge_and_diff_scopes(ctx, completed_stages, current_scope)

    # Removed targets are filtered out
    assert "target.com" not in ctx.result.scope_entries
    assert "example.com" in ctx.result.scope_entries
    assert "new.com" in ctx.result.scope_entries

    assert "a.example.com" in ctx.subdomains
    assert "b.target.com" not in ctx.subdomains
    assert "other.com" not in ctx.subdomains

    assert "https://a.example.com/path" in ctx.urls
    assert "https://b.target.com/path" not in ctx.urls

    assert len(ctx.reportable_findings) == 1
    assert ctx.reportable_findings[0]["url"] == "https://a.example.com/path"

    # completed_stages is cleared because new.com was added
    assert not completed_stages


@pytest.mark.asyncio
async def test_adaptive_scan_cancellation_shield() -> None:
    import asyncio

    from src.decision.adaptive_scan import AdaptiveScanCoordinator

    async def mock_probe(url: str) -> list[dict]:
        await asyncio.sleep(0.1)
        return [{"url": url, "category": "mock_vuln"}]

    coordinator = AdaptiveScanCoordinator(
        urls=["http://target1.com", "http://target2.com"],
        probe_fn=mock_probe,
        batch_size=1,
        concurrency=1,
    )

    deltas_saved = []
    def save_delta_fn(urls, findings):
        deltas_saved.append((urls, findings))

    # Cancel the run loop after starting
    async def run_and_cancel():
        run_task = asyncio.create_task(coordinator.run(save_delta_fn=save_delta_fn))
        await asyncio.sleep(0.05)
        run_task.cancel()
        try:
            await run_task
        except asyncio.CancelledError:
            pass

    await run_and_cancel()

    # Verifies that at least the first batch finishes scanning, flushes delta, and registers findings before cancelling
    assert len(deltas_saved) == 1
    assert deltas_saved[0][0] == ["http://target1.com"]
    assert len(deltas_saved[0][1]) == 1

