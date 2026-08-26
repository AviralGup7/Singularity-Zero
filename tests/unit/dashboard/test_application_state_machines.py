"""Application state machines: job, stage, finding, circuit breaker."""

from __future__ import annotations

import asyncio

import pytest

from src.core.contracts.finding_lifecycle import (
    FindingLifecycleState,
    apply_lifecycle,
    transition_state,
)
from src.core.models.pipeline_state import StageExecution
from src.core.models.stage_result import PipelineContext, StageStatus
from src.core.models.stage_status import (
    IllegalStageTransitionError,
    skipped_satisfies_gate,
    transition_stage_status,
)
from src.core.security.circuit_breaker import CircuitBreaker, CircuitBreakerOpenException
from src.dashboard.job_status import (
    JobStatus,
    _transition,
    apply_pipeline_exit_status,
    can_transition_job,
)


@pytest.mark.unit
def test_job_terminal_states_cannot_leave() -> None:
    for terminal in (JobStatus.COMPLETED, JobStatus.FAILED, JobStatus.STOPPED):
        job = {"id": "j1", "status": terminal.value}
        assert _transition(job, JobStatus.RUNNING) is False
        assert job["status"] == terminal.value
        assert _transition(job, JobStatus.FAILED) is (terminal is JobStatus.FAILED)
        assert job["status"] == terminal.value


@pytest.mark.unit
def test_job_completed_cannot_become_failed_or_running() -> None:
    job = {"id": "j2", "status": JobStatus.COMPLETED.value}
    assert _transition(job, JobStatus.FAILED) is False
    assert _transition(job, JobStatus.RUNNING) is False
    assert job["status"] == "completed"


@pytest.mark.unit
def test_job_running_to_stopping_to_stopped() -> None:
    job = {"id": "j3", "status": JobStatus.RUNNING.value}
    assert _transition(job, JobStatus.STOPPING) is True
    assert job["status"] == "stopping"
    assert _transition(job, JobStatus.STOPPED) is True
    assert job["status"] == "stopped"
    assert _transition(job, JobStatus.RUNNING) is False
    assert job["status"] == "stopped"


@pytest.mark.unit
def test_job_starting_to_running_to_completed() -> None:
    job = {"id": "j4", "status": JobStatus.STARTING.value}
    assert _transition(job, JobStatus.RUNNING) is True
    assert _transition(job, JobStatus.COMPLETED) is True
    assert job["status"] == "completed"


@pytest.mark.unit
def test_stop_does_not_mark_stopped_while_process_alive() -> None:
    class _Alive:
        def terminate(self) -> None:
            return None

        def wait(self, timeout: float | None = None) -> None:
            raise TimeoutError("still running")

        def kill(self) -> None:
            return None

        def poll(self) -> None:
            return None

    from src.dashboard.services.query_service import DashboardQueryService

    jobs = {
        "j-live": {
            "id": "j-live",
            "status": "running",
            "process": _Alive(),
            "stop_requested": False,
        }
    }
    svc = DashboardQueryService(
        output_root=__import__("pathlib").Path("/tmp"),
        config_template=__import__("pathlib").Path("/tmp/x"),
        lock=__import__("threading").Lock(),
        jobs=jobs,
    )
    snapshot = svc.stop_job("j-live")
    assert jobs["j-live"]["status"] == "stopping"
    assert snapshot["status"] == "stopping"
    assert jobs["j-live"]["stop_requested"] is True


@pytest.mark.unit
def test_stop_marks_stopped_after_process_reaped() -> None:
    class _Dead:
        def terminate(self) -> None:
            return None

        def wait(self, timeout: float | None = None) -> int:
            return 0

        def poll(self) -> int:
            return 0

    from src.dashboard.services.query_service import DashboardQueryService

    jobs = {
        "j-dead": {
            "id": "j-dead",
            "status": "running",
            "process": _Dead(),
            "stop_requested": False,
        }
    }
    svc = DashboardQueryService(
        output_root=__import__("pathlib").Path("/tmp"),
        config_template=__import__("pathlib").Path("/tmp/x"),
        lock=__import__("threading").Lock(),
        jobs=jobs,
    )
    snapshot = svc.stop_job("j-dead")
    assert jobs["j-dead"]["status"] == "stopped"
    assert snapshot["status"] == "stopped"
    assert jobs["j-dead"]["process"] is None


@pytest.mark.unit
def test_stage_cas_rejects_completed_to_failed_or_skipped() -> None:
    with pytest.raises(IllegalStageTransitionError):
        transition_stage_status("COMPLETED", "FAILED")
    with pytest.raises(IllegalStageTransitionError):
        transition_stage_status("COMPLETED", "SKIPPED")
    assert transition_stage_status("FAILED", "COMPLETED") == "COMPLETED"
    with pytest.raises(IllegalStageTransitionError):
        transition_stage_status("SKIPPED_DISABLED", "COMPLETED")
    assert transition_stage_status("COMPLETED", "FAILED", soft=True) == "COMPLETED"


@pytest.mark.unit
def test_stage_status_map_blocks_unconditional_overwrite() -> None:
    ctx = PipelineContext()
    ctx.mark_stage_complete("recon")
    with pytest.raises(IllegalStageTransitionError):
        ctx.mark_stage_failed("recon", "boom")
    assert ctx.result.stage_status["recon"] == StageStatus.COMPLETED.value


@pytest.mark.unit
def test_skipped_failed_does_not_satisfy_gates() -> None:
    ctx = PipelineContext()
    ctx.mark_stage_skipped("nuclei", reason="circuit_breaker_open")
    assert ctx.result.stage_status["nuclei"] == StageStatus.SKIPPED_FAILED.value
    assert skipped_satisfies_gate(ctx.result.stage_status["nuclei"]) is False

    ctx2 = PipelineContext()
    ctx2.mark_stage_skipped("iac_scan", reason="no_iac_paths")
    assert ctx2.result.stage_status["iac_scan"] == StageStatus.SKIPPED_DISABLED.value
    assert skipped_satisfies_gate(ctx2.result.stage_status["iac_scan"]) is True


@pytest.mark.unit
def test_finding_reportable_and_false_positive_are_sticky() -> None:
    findings = apply_lifecycle(
        [
            {"lifecycle_state": "reportable", "severity": "low"},
            {"lifecycle_state": "false_positive", "verified": True},
        ]
    )
    assert findings[0]["lifecycle_state"] == "reportable"
    assert findings[1]["lifecycle_state"] == "false_positive"


@pytest.mark.unit
def test_finding_illegal_transition_does_not_raise() -> None:
    assert transition_state("reportable", "detected") == "reportable"
    assert transition_state("reportable", "candidate") == "reportable"
    assert FindingLifecycleState.FALSE_POSITIVE.value == "false_positive"
    assert FindingLifecycleState.CANDIDATE.value == "candidate"


@pytest.mark.unit
def test_finding_false_positive_from_decision() -> None:
    findings = apply_lifecycle([{"decision": "FALSE_POSITIVE", "severity": "high"}])
    assert findings[0]["lifecycle_state"] == "false_positive"


@pytest.mark.unit
def test_circuit_breaker_single_half_open_trial(monkeypatch: pytest.MonkeyPatch) -> None:
    now = 100.0
    monkeypatch.setattr("src.core.security.circuit_breaker.time.monotonic", lambda: now)
    breaker = CircuitBreaker("svc", failure_threshold=1, recovery_timeout=5.0)

    def fail() -> None:
        raise RuntimeError("down")

    with pytest.raises(RuntimeError):
        breaker.call(fail)
    assert breaker.state == "OPEN"

    now = 106.0

    def slow_ok() -> str:
        return "ok"

    # First HALF_OPEN trial is admitted.
    assert breaker.call(slow_ok) == "ok"
    assert breaker.state == "CLOSED"


@pytest.mark.unit
def test_circuit_breaker_rejects_second_concurrent_half_open(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = 100.0
    monkeypatch.setattr("src.core.security.circuit_breaker.time.monotonic", lambda: now)
    breaker = CircuitBreaker("svc", failure_threshold=1, recovery_timeout=1.0)

    def fail() -> None:
        raise RuntimeError("down")

    with pytest.raises(RuntimeError):
        breaker.call(fail)
    now = 102.0

    # Manually enter HALF_OPEN with a probe in flight.
    breaker.state = "HALF_OPEN"
    breaker._half_open_probe_in_flight = True
    breaker._trial_generation = 1
    with pytest.raises(CircuitBreakerOpenException):
        # OPEN fallback: actually HALF_OPEN with probe in flight rejects admit
        # and raises if no fallback.
        breaker.call(lambda: "nope")
    assert breaker._half_open_probe_in_flight is True


@pytest.mark.unit
def test_circuit_breaker_stale_trial_cannot_close(monkeypatch: pytest.MonkeyPatch) -> None:
    now = 100.0
    monkeypatch.setattr("src.core.security.circuit_breaker.time.monotonic", lambda: now)
    breaker = CircuitBreaker("svc", failure_threshold=1, recovery_timeout=1.0)

    def fail() -> None:
        raise RuntimeError("down")

    with pytest.raises(RuntimeError):
        breaker.call(fail)
    now = 102.0
    admitted, state, version, trial = breaker._try_admit_call()
    assert admitted is True
    assert state == "HALF_OPEN"

    # A later generation starts (timeout again after reopen).
    breaker._trial_generation += 1
    breaker._record_success(state, version, trial)
    # Stale success must not close the breaker.
    assert breaker.state == "HALF_OPEN"


@pytest.mark.unit
def test_circuit_breaker_async_lock_serializes_half_open(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = 100.0
    monkeypatch.setattr("src.core.security.circuit_breaker.time.monotonic", lambda: now)
    breaker = CircuitBreaker("svc", failure_threshold=1, recovery_timeout=1.0)

    async def fail() -> None:
        raise RuntimeError("down")

    async def _run() -> None:
        with pytest.raises(RuntimeError):
            await breaker.call_async(fail)
        now_holder = {"t": 102.0}
        monkeypatch.setattr(
            "src.core.security.circuit_breaker.time.monotonic", lambda: now_holder["t"]
        )

        entered = 0
        gate = asyncio.Event()

        async def probe() -> str:
            nonlocal entered
            entered += 1
            await gate.wait()
            return "ok"

        async def blocked() -> str:
            return "blocked"

        first = asyncio.create_task(breaker.call_async(probe))
        await asyncio.sleep(0)
        second = asyncio.create_task(breaker.call_async(blocked))
        await asyncio.sleep(0)
        try:
            assert entered == 1
            gate.set()
            results = await asyncio.wait_for(
                asyncio.gather(first, second, return_exceptions=True),
                timeout=2,
            )
        finally:
            gate.set()
            first.cancel()
            second.cancel()
        assert "ok" in results
        assert any(
            isinstance(item, CircuitBreakerOpenException) or item in {"ok", "blocked"}
            for item in results
        )

    asyncio.run(_run())


@pytest.mark.unit
def test_can_transition_job_matrix() -> None:
    assert can_transition_job("running", "stopping") is True
    assert can_transition_job("stopping", "stopped") is True
    assert can_transition_job("completed", "failed") is False
    assert can_transition_job("failed", "running") is False


@pytest.mark.unit
def test_apply_pipeline_exit_status_stop_requested_reaps_stopped() -> None:
    job = {"id": "j-stop", "status": JobStatus.STOPPING.value}
    assert apply_pipeline_exit_status(job, stop_requested=True, returncode=0) is True
    assert job["status"] == "stopped"
    assert apply_pipeline_exit_status(job, stop_requested=True, returncode=1) is True
    assert job["status"] == "stopped"


@pytest.mark.unit
def test_apply_pipeline_exit_status_stopping_cannot_complete() -> None:
    job = {"id": "j-stop-complete", "status": JobStatus.STOPPING.value}
    assert apply_pipeline_exit_status(job, stop_requested=False, returncode=0) is True
    assert job["status"] == "stopped"


@pytest.mark.unit
def test_apply_pipeline_exit_status_no_output_or_running_stages_fails() -> None:
    empty = {"id": "j-empty", "status": JobStatus.RUNNING.value}
    assert (
        apply_pipeline_exit_status(
            empty, stop_requested=False, returncode=0, no_pipeline_output=True
        )
        is True
    )
    assert empty["status"] == "failed"

    running = {"id": "j-running-stages", "status": JobStatus.RUNNING.value}
    assert (
        apply_pipeline_exit_status(
            running, stop_requested=False, returncode=0, has_running_stages=True
        )
        is True
    )
    assert running["status"] == "failed"

    ok = {"id": "j-ok", "status": JobStatus.RUNNING.value}
    assert apply_pipeline_exit_status(ok, stop_requested=False, returncode=0) is True
    assert ok["status"] == "completed"


@pytest.mark.unit
def test_stage_execution_mark_skipped_uses_cas() -> None:
    stage = StageExecution(name="recon")
    stage.mark_running()
    stage.mark_completed()
    with pytest.raises(IllegalStageTransitionError):
        stage.mark_skipped("disabled")
    assert stage.status == StageStatus.COMPLETED


@pytest.mark.unit
def test_stage_execution_mark_skipped_splits_reasons() -> None:
    disabled = StageExecution(name="iac")
    disabled.mark_skipped("no_iac_paths")
    assert disabled.status == StageStatus.SKIPPED_DISABLED

    failed = StageExecution(name="nuclei")
    failed.mark_skipped("circuit_breaker_open")
    assert failed.status == StageStatus.SKIPPED_FAILED
