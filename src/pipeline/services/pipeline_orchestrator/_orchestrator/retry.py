"""Stage retry execution module with backoff, budget isolation, event emission, and causal tracing."""

from __future__ import annotations

import argparse
import asyncio
import inspect
import time
from datetime import UTC, datetime
from typing import Any

from src.core.contracts.pipeline_runtime import StageOutcome, StageOutput
from src.core.events import EventType
from src.core.frontier.tracing_manager import get_tracing_manager
from src.core.logging.trace_logging import get_pipeline_logger
from src.core.models.stage_result import PipelineContext, StageStatus
from src.infrastructure.observability.trace_store import (
    StageTrace,
    _truncate,
    build_tool_invocation,
    compute_stage_input_hash,
    extract_findings_from_output,
    get_trace_store,
    make_trace_id,
    redact_tool_invocation,
)
from src.pipeline.retry import (
    AdaptiveBackoffHeuristic,
    CircuitState,
    RetryEventEmitter,
    RetryEventType,
    RetryMetrics,
    RetryPolicy,
    RetryPolicyState,
    StageRetryPolicy,
    ToolCircuitBreaker,
    classify_error,
    is_retryable,
    sleep_before_retry_async,
)

logger = get_pipeline_logger(__name__)
_retry_emitter = RetryEventEmitter()

_DEFAULT_RETRY_BUDGET_SECONDS: float = 0.0


async def _record_trace(
    *,
    orchestrator: Any,
    stage_name: str,
    stage_input: Any,
    method: Any,
    stage_output: StageOutput | None,
    started: float,
    finished: float,
    error: str | None,
    run_id: str,
    finding_event_ids: list[str],
    retry_count: int,
) -> None:
    trace_store = get_trace_store()
    finished_dt = datetime.fromtimestamp(finished, tz=UTC)
    started_dt = datetime.fromtimestamp(started, tz=UTC)
    duration_ms = round((finished - started) * 1000, 3)
    state_pre_count = 0
    state_post_count = 0
    state_delta_keys: list[str] = []
    findings_produced: list[str] = []
    tool_stdout: str | None = None
    tool_stderr: str | None = None
    exit_code: int | None = None

    if stage_output is not None:
        delta = getattr(stage_output, "state_delta", {}) or {}
        if isinstance(delta, dict):
            state_delta_keys = sorted(str(k) for k in delta.keys())
            findings_produced = extract_findings_from_output(stage_output)
        state_post_count = len(delta)
        metrics = getattr(stage_output, "metrics", {}) or {}
        if isinstance(metrics, dict):
            raw_stdout = metrics.get("stdout") or metrics.get("tool_stdout")
            raw_stderr = metrics.get("stderr") or metrics.get("tool_stderr")
            if isinstance(raw_stdout, str):
                tool_stdout = _truncate(raw_stdout)
            if isinstance(raw_stderr, str):
                tool_stderr = _truncate(raw_stderr)
            exit_code = metrics.get("exit_code")
            if not isinstance(exit_code, int):
                exit_code = None
        state_pre_count = max(0, state_post_count - len(findings_produced))
    else:
        state_pre_count = 0
        state_post_count = 0
        state_delta_keys = []
        findings_produced = []

    invocation = redact_tool_invocation(build_tool_invocation(stage_input, method))
    trace = StageTrace(
        trace_id=make_trace_id(),
        run_id=run_id,
        stage_name=stage_name,
        started_at=started_dt,
        finished_at=finished_dt,
        duration_ms=duration_ms,
        stage_input_hash=compute_stage_input_hash(stage_input),
        tool_invocation=invocation,
        tool_stdout=tool_stdout,
        tool_stderr=tool_stderr,
        exit_code=exit_code,
        state_delta_keys=state_delta_keys,
        state_pre_count=state_pre_count,
        state_post_count=state_post_count,
        findings_produced=findings_produced,
        finding_event_ids=finding_event_ids,
        error=error,
        retry_count=retry_count,
    )
    try:
        await trace_store.record_trace_async(trace)
    except Exception:
        trace_store.record_trace(trace)


async def run_stage_with_retry(
    orchestrator: Any,
    stage_name: str,
    method: Any,
    args: argparse.Namespace,
    config: Any,
    ctx: PipelineContext,
    timeout: int,
    scope_interceptor: Any,
    progress_emitter: Any,
    previous_deltas: list[dict[str, Any]] | None = None,
    circuit_breaker: ToolCircuitBreaker | None = None,
    critical: bool = False,
) -> StageOutput | None:
    """Run a single stage with timeout and StageRetryPolicy-managed backoff."""
    if getattr(ctx.result, "cancel_requested", False):
        logger.info("Cancel requested, skipping stage %s", stage_name)
        ctx.result.module_metrics[stage_name] = {
            "status": "skipped",
            "reason": "cancel_requested",
        }
        ctx.result.stage_status[stage_name] = StageStatus.SKIPPED.value
        progress_emitter(
            stage_name,
            f"Skipped stage {stage_name}: cancel requested",
            orchestrator._stage_baseline(stage_name),
            status="skipped",
            stage_status="skipped",
            reason="cancel_requested",
            event_trigger="stage_skipped",
        )
        orchestrator._emit_event(
            EventType.STAGE_SKIPPED,
            source=f"stage.{stage_name}",
            data={"contract": orchestrator._build_stage_output_contract(stage_name, 0.0, ctx)},
        )
        return None

    policy = orchestrator._get_stage_retry_policy(config)
    if isinstance(policy, RetryPolicyState) and not isinstance(policy, StageRetryPolicy):
        policy = StageRetryPolicy(
            base_policy=policy.base_policy,
            adaptive_heuristic=policy.adaptive_heuristic,
            max_retry_budget_seconds=_DEFAULT_RETRY_BUDGET_SECONDS,
        )
    if not isinstance(policy, StageRetryPolicy):
        policy = StageRetryPolicy(
            base_policy=RetryPolicy(
                max_attempts=getattr(policy, "max_attempts", 1),
                initial_backoff_seconds=getattr(policy, "initial_backoff_seconds", 0.0),
                backoff_multiplier=getattr(policy, "backoff_multiplier", 2.0),
                max_backoff_seconds=getattr(policy, "max_backoff_seconds", 8.0),
                retry_on_timeout=getattr(policy, "retry_on_timeout", True),
                retry_on_error=getattr(policy, "retry_on_error", True),
                jitter_factor=getattr(policy, "jitter_factor", 0.25),
            ),
            adaptive_heuristic=AdaptiveBackoffHeuristic(),
            max_retry_budget_seconds=_DEFAULT_RETRY_BUDGET_SECONDS,
        )
    if circuit_breaker is not None and not circuit_breaker.can_execute(stage_name):
        skip_reason = circuit_breaker.get_skip_reason(stage_name)
        logger.info("Circuit breaker OPEN for stage '%s': %s", stage_name, skip_reason)
        _retry_emitter.emit(
            RetryEventType.RETRY_EXHAUSTED,
            stage=stage_name,
            attempt=0,
            max_attempts=policy.max_attempts,
            classification="circuit_open",
            error=skip_reason or "Circuit breaker open",
            backoff_seconds=0.0,
            total_backoff_seconds=0.0,
        )
        progress_emitter(
            stage_name,
            f"Skipped stage {stage_name}: {skip_reason}",
            orchestrator._stage_baseline(stage_name),
            status="skipped",
            stage_status="skipped",
            reason="circuit_breaker_open",
            error=skip_reason or "Circuit breaker open",
            event_trigger="stage_skipped",
        )
        orchestrator._emit_event(
            EventType.STAGE_SKIPPED,
            source=f"stage.{stage_name}",
            data={
                "contract": ctx.build_stage_output(stage_name, 0.0).to_dict(),
                "skip_reason": skip_reason,
                "circuit_state": CircuitState.OPEN.value,
            },
        )
        ctx.result.stage_status[stage_name] = StageStatus.SKIPPED.value
        ctx.result.module_metrics[stage_name] = {
            "status": "skipped",
            "reason": "circuit_breaker_open",
            "error": skip_reason,
            "retry_count": 0,
        }
        return StageOutput(
            stage_name=stage_name,
            outcome=StageOutcome.SKIPPED,
            duration_seconds=0.0,
            reason="circuit_breaker_open",
            error=skip_reason or "Circuit breaker open",
            metrics={
                "circuit_state": CircuitState.OPEN.value,
                "skip_reason": skip_reason,
                "retry_metrics": {
                    "attempts": 0,
                    "transient_errors": 0,
                    "backoff_seconds": 0.0,
                },
            },
        )
    metrics = RetryMetrics()
    shutdown_event = (
        orchestrator._shutdown_event if hasattr(orchestrator, "_shutdown_event") else None
    )

    async def _execute_stage() -> StageOutput | None:
        isolated_ctx = PipelineContext.restore(ctx.to_dict())
        isolated_ctx.output_store = ctx.output_store
        if hasattr(orchestrator, "_checkpoint_mgr"):
            isolated_ctx._checkpoint_mgr = orchestrator._checkpoint_mgr
        elif "checkpoint_mgr" in locals() or "checkpoint_mgr" in globals():
            pass

        pre_snapshot = ctx.result.to_dict()
        started = time.monotonic()
        run_id = getattr(orchestrator._pipeline_input, "run_id", "") or getattr(ctx, "run_id", "")

        stage_input = isolated_ctx.build_stage_input(
            stage_name=stage_name,
            stage_index=0,
            stage_total=0,
            pipeline_input=orchestrator._pipeline_input,
            runtime={
                "mode": str(getattr(config, "mode", "default") or "default"),
                "filters": dict(getattr(config, "filters", {}) or {}),
            },
            previous_deltas=previous_deltas,
        )
        stage_trace_id = make_trace_id()

        tracer = get_tracing_manager()
        with tracer.start_stage_span(stage_name, args, config, isolated_ctx) as span:
            try:
                sig = inspect.signature(method)
                accepts_stage_input = "stage_input" in sig.parameters
            except (ValueError, TypeError):
                accepts_stage_input = True

            if stage_name == "nuclei":
                if accepts_stage_input:
                    res_or_coro = method(
                        args, config, isolated_ctx, scope_interceptor, stage_input=stage_input
                    )
                else:
                    res_or_coro = method(args, config, isolated_ctx, scope_interceptor)
            else:
                if accepts_stage_input:
                    res_or_coro = method(args, config, isolated_ctx, stage_input=stage_input)
                else:
                    res_or_coro = method(args, config, isolated_ctx)

            if inspect.iscoroutine(res_or_coro) or asyncio.iscoroutine(res_or_coro):
                result = await asyncio.wait_for(res_or_coro, timeout=timeout)
            else:
                result = res_or_coro

        elapsed = time.monotonic() - started
        post_snapshot = isolated_ctx.result.to_dict()
        state_delta = {
            key: value
            for key, value in post_snapshot.items()
            if pre_snapshot.get(key) != value
            and key not in {"output_store", "module_metrics", "stage_status", "_neural_state"}
            and not key.startswith("_")
        }

        try:
            from src.infrastructure.observability.metrics import get_metrics as _get_metrics

            _reg = _get_metrics()
            _reg.histogram("scan_duration_seconds", labels={"stage": stage_name}).observe(elapsed)
            _reg.counter("total_jobs").inc()
        except Exception:  # noqa: BLE001
            pass

        if isinstance(result, StageOutput):
            import dataclasses

            merged_delta = {**state_delta, **(result.state_delta or {})}
            result = dataclasses.replace(result, state_delta=merged_delta)
            tracer.record_stage_result(span, result)

            try:
                from src.infrastructure.observability.metrics import get_metrics as _get_metrics

                _get_metrics().counter("completed_jobs").inc()
            except Exception:  # noqa: BLE001
                pass

            orchestrator._emit_event(
                EventType.STAGE_COMPLETED,
                source=f"stage.{stage_name}",
                data={
                    "contract": orchestrator._build_stage_output_contract(stage_name, elapsed, ctx),
                    "trace_id": stage_trace_id,
                },
                trace_id=stage_trace_id,
            )
            return result

        stage_metrics = isolated_ctx.result.module_metrics.get(stage_name, {})
        stage_state = str(
            isolated_ctx.result.stage_status.get(stage_name, StageStatus.COMPLETED.value)
        )
        output = StageOutput.from_stage_state(
            stage_name=stage_name,
            state=stage_state,
            duration_seconds=float(
                (stage_metrics.get("duration_seconds") if isinstance(stage_metrics, dict) else 0.0)
                or elapsed
            ),
            metrics=stage_metrics if isinstance(stage_metrics, dict) else {},
            state_delta=state_delta,
        )
        tracer.record_stage_result(span, output)

        try:
            from src.infrastructure.observability.metrics import get_metrics as _get_metrics

            _get_metrics().counter("completed_jobs").inc()
        except Exception:  # noqa: BLE001
            pass

        orchestrator._emit_event(
            EventType.STAGE_COMPLETED,
            source=f"stage.{stage_name}",
            data={
                "contract": orchestrator._build_stage_output_contract(stage_name, elapsed, ctx),
                "trace_id": stage_trace_id,
            },
            trace_id=stage_trace_id,
        )
        return output

    last_exc: BaseException | None = None
    is_timeout = False
    stage_input: Any = None
    stage_started = time.monotonic()

    def _format_stage_error(exc: BaseException | None, *, timed_out: bool) -> str:
        if exc is None:
            return f"Stage {stage_name} failed"
        raw = str(exc).strip()
        if raw:
            return raw
        if timed_out:
            return f"Stage {stage_name} timed out after {timeout}s"
        return exc.__class__.__name__

    for attempt in range(1, policy.max_attempts + 1):
        metrics.record_attempt()
        try:
            stage_output = await _execute_stage()
            metrics.record_success()
            policy.observe_outcome(True)
            if circuit_breaker is not None:
                circuit_breaker.record_success(stage_name)
            if stage_output is not None:
                import dataclasses

                from src.core.contracts.pipeline_runtime import _thaw_value

                new_metrics = dict(_thaw_value(stage_output.metrics))
                new_metrics["retry_metrics"] = {
                    "attempts": metrics.total_attempts,
                    "transient_errors": metrics.transient_errors,
                    "backoff_seconds": round(metrics.total_backoff_seconds, 2),
                }
                stage_output = dataclasses.replace(stage_output, metrics=new_metrics)
            if attempt > 1:
                progress_emitter(
                    stage_name,
                    f"Stage {stage_name} recovered after {attempt} attempts",
                    orchestrator._stage_baseline(stage_name),
                    status="running",
                    stage_status="running",
                    retry_count=attempt - 1,
                    event_trigger="stage_recovered",
                )
            _retry_emitter.emit(
                RetryEventType.RETRY_SUCCESS,
                stage=stage_name,
                attempt=attempt,
                max_attempts=policy.max_attempts,
                classification="none",
                error="",
                backoff_seconds=0.0,
                total_backoff_seconds=metrics.total_backoff_seconds,
            )
            run_id = getattr(orchestrator._pipeline_input, "run_id", "") or getattr(
                ctx, "run_id", ""
            )
            stage_trace_id = getattr(stage_output, "trace_id", "") if stage_output else ""
            await _record_trace(
                orchestrator=orchestrator,
                stage_name=stage_name,
                stage_input=stage_input,
                method=method,
                stage_output=stage_output,
                started=stage_started,
                finished=time.monotonic(),
                error=None,
                run_id=run_id,
                finding_event_ids=[stage_trace_id] if stage_trace_id else [],
                retry_count=max(0, attempt - 1),
            )
            return stage_output

        except (TimeoutError, asyncio.TimeoutError) as exc:  # noqa: UP041
            last_exc = exc
            is_timeout = True
            classification = "transient"
            metrics.record_transient()
            policy.observe_outcome(False)
            if circuit_breaker is not None:
                circuit_breaker.record_failure(stage_name, classification)
            if stage_name == "live_hosts":
                orchestrator._log_live_hosts_timeout_diagnostics(ctx, timeout)

        except asyncio.CancelledError:
            ctx.result.module_metrics[stage_name] = {
                "status": "cancelled",
                "reason": "execution_cancelled",
            }
            raise

        except Exception as exc:
            last_exc = exc
            is_timeout = False
            classification = classify_error(exc)
            if classification == "transient":
                metrics.record_transient()
            elif classification == "permanent":
                metrics.record_permanent()
            policy.observe_outcome(False)
            if circuit_breaker is not None:
                circuit_breaker.record_failure(stage_name, classification)

        retryable = (
            last_exc is not None
            and policy.retry_on_error is True
            and attempt < policy.max_attempts
            and is_retryable(last_exc, policy)
        )

        if not retryable:
            metrics.record_failure()
            try:
                from src.infrastructure.observability.metrics import get_metrics as _get_metrics

                _get_metrics().counter("failed_jobs").inc()
            except Exception:  # noqa: BLE001
                pass
            stage_error = _format_stage_error(last_exc, timed_out=is_timeout)
            ctx.result.stage_status[stage_name] = StageStatus.FAILED.value
            ctx.result.module_metrics[stage_name] = {
                "status": "timeout" if is_timeout else "failed",
                "duration_seconds": timeout if is_timeout else None,
                "error": stage_error,
                "failure_reason": stage_error,
                "retries_exhausted": attempt,
                "retry_count": max(0, attempt - 1),
                "fatal": critical,
            }
            _retry_emitter.emit(
                RetryEventType.RETRY_EXHAUSTED,
                stage=stage_name,
                attempt=attempt,
                max_attempts=policy.max_attempts,
                classification=classification,
                error=stage_error,
                backoff_seconds=0.0,
                total_backoff_seconds=metrics.total_backoff_seconds,
            )
            progress_emitter(
                stage_name,
                f"Stage failed ({stage_name}): {stage_error}",
                orchestrator._stage_baseline(stage_name),
                status="error",
                stage_status="error",
                retry_count=max(0, attempt - 1),
                failed_stage=stage_name,
                failure_reason_code="stage_timeout" if is_timeout else "stage_execution_failed",
                failure_reason=stage_error,
                reason=classification,
                error=stage_error,
                details={
                    "attempt": attempt,
                    "max_attempts": policy.max_attempts,
                    "classification": classification,
                    "timeout_seconds": timeout if is_timeout else None,
                },
                event_trigger="stage_failed",
                fatal=critical,
            )
            orchestrator._emit_event(
                EventType.STAGE_FAILED,
                source=f"stage.{stage_name}",
                data={
                    "contract": orchestrator._build_stage_output_contract(
                        stage_name, float(timeout), ctx
                    )
                },
            )
            run_id = getattr(orchestrator._pipeline_input, "run_id", "") or getattr(
                ctx, "run_id", ""
            )
            await _record_trace(
                orchestrator=orchestrator,
                stage_name=stage_name,
                stage_input=stage_input,
                method=method,
                stage_output=None,
                started=stage_started,
                finished=time.monotonic(),
                error=stage_error,
                run_id=run_id,
                finding_event_ids=[],
                retry_count=max(0, attempt - 1),
            )
            return None

        backoff = policy.delay_for_attempt(attempt + 1, jitter=policy.jitter_factor)

        try:
            from src.infrastructure.observability.metrics import get_metrics as _get_metrics

            _get_metrics().counter("retries_total").inc()
        except Exception:  # noqa: BLE001
            pass

        if policy.is_budget_exhausted():
            err = "Stage retry budget exhausted"
            metrics.record_failure()
            _retry_emitter.emit(
                RetryEventType.RETRY_BUDGET_EXHAUSTED,
                stage=stage_name,
                attempt=attempt,
                max_attempts=policy.max_attempts,
                classification=classification,
                error=err,
                backoff_seconds=0.0,
                total_backoff_seconds=metrics.total_backoff_seconds,
            )
            ctx.result.stage_status[stage_name] = StageStatus.FAILED.value
            ctx.result.module_metrics[stage_name] = {
                "status": "failed",
                "error": err,
                "retry_count": max(0, attempt - 1),
                "fatal": critical,
                "retry_metrics": {
                    "attempts": metrics.total_attempts,
                    "transient_errors": metrics.transient_errors,
                    "backoff_seconds": metrics.total_backoff_seconds,
                },
            }
            progress_emitter(
                stage_name,
                f"Stage {stage_name}: {err}",
                orchestrator._stage_baseline(stage_name),
                status="error",
                stage_status="error",
                retry_count=max(0, attempt - 1),
                failed_stage=stage_name,
                failure_reason_code="stage_retry_budget_exhausted",
                failure_reason=err,
                error=err,
                details={
                    "attempt": attempt,
                    "max_attempts": policy.max_attempts,
                    "classification": classification,
                    "budget_remaining_seconds": policy.budget_remaining(),
                },
                event_trigger="stage_failed",
                fatal=critical,
            )
            orchestrator._emit_event(
                EventType.STAGE_FAILED,
                source=f"stage.{stage_name}",
                data={
                    "contract": orchestrator._build_stage_output_contract(
                        stage_name, float(timeout), ctx
                    )
                },
            )
            run_id = getattr(orchestrator._pipeline_input, "run_id", "") or getattr(
                ctx, "run_id", ""
            )
            await _record_trace(
                orchestrator=orchestrator,
                stage_name=stage_name,
                stage_input=stage_input,
                method=method,
                stage_output=None,
                started=stage_started,
                finished=time.monotonic(),
                error=err,
                run_id=run_id,
                finding_event_ids=[],
                retry_count=max(0, attempt - 1),
            )
            return None

        policy.consume_budget(backoff)
        metrics.record_retry(backoff)
        stage_error = _format_stage_error(last_exc, timed_out=is_timeout)
        logger.warning(
            "Stage %s %s (attempt %d/%d), retrying in %.2fs (%s): %s",
            stage_name,
            "timed out" if is_timeout else "failed",
            attempt,
            policy.max_attempts,
            backoff,
            classification,
            stage_error,
        )

        _retry_emitter.emit(
            RetryEventType.RETRY_ATTEMPT,
            stage=stage_name,
            attempt=attempt,
            max_attempts=policy.max_attempts,
            classification=classification,
            error=stage_error,
            backoff_seconds=backoff,
            total_backoff_seconds=metrics.total_backoff_seconds,
        )

        progress_emitter(
            stage_name,
            f"Retrying stage {stage_name} ({attempt}/{policy.max_attempts}) after {classification} error",
            orchestrator._stage_baseline(stage_name),
            status="running",
            stage_status="running",
            retry_count=attempt,
            reason=classification,
            error=stage_error,
            details={
                "attempt": attempt,
                "max_attempts": policy.max_attempts,
                "retry_delay_seconds": round(backoff, 2),
                "classification": classification,
                "budget_remaining_seconds": round(policy.budget_remaining(), 2),
            },
            event_trigger="stage_retry",
        )
        orchestrator._emit_event(
            EventType.STAGE_RETRY,
            source=f"stage.{stage_name}",
            data={
                "stage": stage_name,
                "attempt": attempt,
                "max_attempts": policy.max_attempts,
                "classification": classification,
                "retry_delay_seconds": round(backoff, 2),
                "error": stage_error,
                "budget_remaining_seconds": policy.budget_remaining(),
                "adaptive_backoff_multiplier": round(policy.backoff_multiplier, 3),
            },
        )
        if backoff > 0:
            try:
                await sleep_before_retry_async(policy, attempt, shutdown_event=shutdown_event)
            except asyncio.CancelledError:
                metrics.record_failure()
                raise

    metrics.record_failure()
    _retry_emitter.emit(
        RetryEventType.RETRY_EXHAUSTED,
        stage=stage_name,
        attempt=policy.max_attempts,
        max_attempts=policy.max_attempts,
        classification="unknown",
        error="max retries exhausted",
        backoff_seconds=0.0,
        total_backoff_seconds=metrics.total_backoff_seconds,
    )
    ctx.result.stage_status[stage_name] = StageStatus.FAILED.value
    ctx.result.module_metrics[stage_name] = {
        "status": "failed",
        "error": "max retries exhausted",
        "retry_count": max(0, policy.max_attempts - 1),
        "fatal": critical,
        "retry_metrics": {
            "attempts": metrics.total_attempts,
            "transient_errors": metrics.transient_errors,
            "backoff_seconds": metrics.total_backoff_seconds,
        },
    }
    progress_emitter(
        stage_name,
        f"Stage failed ({stage_name}): max retries exhausted",
        orchestrator._stage_baseline(stage_name),
        status="error",
        stage_status="error",
        retry_count=max(0, policy.max_attempts - 1),
        failed_stage=stage_name,
        failure_reason_code="stage_retry_exhausted",
        failure_reason="max retries exhausted",
        error="max retries exhausted",
        details={
            "attempts": metrics.total_attempts,
            "transient_errors": metrics.transient_errors,
            "backoff_seconds": round(metrics.total_backoff_seconds, 2),
        },
        event_trigger="stage_failed",
        fatal=critical,
    )
    orchestrator._emit_event(
        EventType.STAGE_FAILED,
        source=f"stage.{stage_name}",
        data={
            "contract": orchestrator._build_stage_output_contract(stage_name, float(timeout), ctx)
        },
    )
    run_id = getattr(orchestrator._pipeline_input, "run_id", "") or getattr(ctx, "run_id", "")
    await _record_trace(
        orchestrator=orchestrator,
        stage_name=stage_name,
        stage_input=stage_input,
        method=method,
        stage_output=None,
        started=stage_started,
        finished=time.monotonic(),
        error="max retries exhausted",
        run_id=run_id,
        finding_event_ids=[],
        retry_count=max(0, policy.max_attempts - 1),
    )
    return None
