import argparse
import asyncio
import time
from typing import Any

from src.core.contracts.pipeline_runtime import StageOutput
from src.core.events import EventType
from src.core.frontier.tracing_manager import get_tracing_manager
from src.core.logging.trace_logging import get_pipeline_logger
from src.core.models.stage_result import PipelineContext, StageStatus
from src.pipeline.retry import RetryMetrics, classify_error

logger = get_pipeline_logger(__name__)


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
) -> StageOutput | None:
    """Run a single stage with timeout and RetryPolicy-managed backoff."""
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
    metrics = RetryMetrics()

    async def _execute_stage() -> StageOutput | None:
        isolated_ctx = PipelineContext.restore(ctx.to_dict())
        isolated_ctx.output_store = ctx.output_store
        # Overhaul #5: Link checkpoint manager for mid-stage delta support
        if hasattr(orchestrator, "_checkpoint_mgr"):
            isolated_ctx._checkpoint_mgr = orchestrator._checkpoint_mgr
        elif "checkpoint_mgr" in locals() or "checkpoint_mgr" in globals():
            # Fallback for different orchestrator structures
            pass

        pre_snapshot = ctx.result.to_dict()
        started = time.monotonic()
        
        # Build formal StageInput with previous_deltas for mid-stage resume
        stage_input = isolated_ctx.build_stage_input(
            stage_name=stage_name,
            stage_index=0,
            stage_total=0,
            pipeline_input=orchestrator._pipeline_input,
            runtime={
                "mode": str(getattr(config, "mode", "default") or "default"),
                "filters": dict(getattr(config, "filters", {}) or {}),
            },
            previous_deltas=previous_deltas
        )

        tracer = get_tracing_manager()
        with tracer.start_stage_span(stage_name, args, config, isolated_ctx) as span:
            if stage_name == "nuclei":
                result = await asyncio.wait_for(
                    method(args, config, isolated_ctx, scope_interceptor, stage_input=stage_input),
                    timeout=timeout,
                )
            else:
                result = await asyncio.wait_for(
                    method(args, config, isolated_ctx, stage_input=stage_input),
                    timeout=timeout,
                )
        elapsed = time.monotonic() - started
        if isinstance(result, StageOutput):
            tracer.record_stage_result(span, result)
            return result

        post_snapshot = isolated_ctx.result.to_dict()
        state_delta = {
            key: value
            for key, value in post_snapshot.items()
            if pre_snapshot.get(key) != value
            and key not in {"output_store", "module_metrics", "stage_status"}
        }
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
        return output

    last_exc: BaseException | None = None
    is_timeout = False

    def _format_stage_error(exc: BaseException | None, *, timed_out: bool) -> str:
        if exc is None:
            if timed_out:
                return f"Stage {stage_name} timed out after {timeout}s"
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
            return stage_output
        except TimeoutError as exc:
            last_exc = exc
            is_timeout = True
            classification = "transient"
            metrics.record_transient()
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

        retryable = (
            classification != "permanent"
            and policy.retry_on_error
            and attempt < policy.max_attempts
        )

        if not retryable:
            metrics.record_failure()
            status = "timeout" if is_timeout else "failed"
            stage_error = _format_stage_error(last_exc, timed_out=is_timeout)
            fatal_stage_failure = stage_name in {"subdomains", "live_hosts", "urls"}
            ctx.result.stage_status[stage_name] = StageStatus.FAILED.value
            ctx.result.module_metrics[stage_name] = {
                "status": status,
                "duration_seconds": timeout if status == "timeout" else None,
                "error": stage_error,
                "failure_reason": stage_error,
                "retries_exhausted": attempt,
                "retry_count": max(0, attempt - 1),
                "fatal": fatal_stage_failure,
            }
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
                fatal=fatal_stage_failure,
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
            return None

        # Apply backoff with jitter from RetryPolicy
        backoff = policy.delay_for_attempt(attempt, jitter=policy.jitter_factor)
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
            },
        )
        if backoff > 0:
            await asyncio.sleep(backoff)

    metrics.record_failure()
    fatal_stage_failure = stage_name in {"subdomains", "live_hosts", "urls"}
    ctx.result.stage_status[stage_name] = StageStatus.FAILED.value
    ctx.result.module_metrics[stage_name] = {
        "status": "failed",
        "error": "max retries exhausted",
        "retry_count": max(0, policy.max_attempts - 1),
        "fatal": fatal_stage_failure,
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
        fatal=fatal_stage_failure,
    )
    orchestrator._emit_event(
        EventType.STAGE_FAILED,
        source=f"stage.{stage_name}",
        data={
            "contract": orchestrator._build_stage_output_contract(stage_name, float(timeout), ctx)
        },
    )
    return None
