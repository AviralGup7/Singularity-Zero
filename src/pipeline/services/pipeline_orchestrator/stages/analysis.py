"""Passive scanning stage with iterative feedback loop and validation."""

import asyncio
import time
from typing import Any

from src.analysis.behavior.analysis import annotate_behavior_history
from src.analysis.intelligence.aggregator import (
    annotate_finding_decisions,
    annotate_finding_history,
    filter_reportable_findings,
    merge_findings,
)
from src.analysis.passive.orchestrator import run_passive_scanners
from src.core.contracts.finding_lifecycle import apply_lifecycle
from src.core.contracts.pipeline_runtime import StageInput, StageOutcome, StageOutput
from src.core.contracts.schema_validator import (
    validate_analysis_payload,
    validate_decision_payload,
    validate_detection_payload,
)
from src.core.logging.trace_logging import get_pipeline_logger
from src.core.models.stage_result import PipelineContext
from src.execution.validators import execute_validation_runtime
from src.pipeline.runner_support import emit_progress
from src.pipeline.services.pipeline_helpers import (
    build_stage_input_from_context,
    extract_feedback_urls,
    finding_identity,
)

logger = get_pipeline_logger(__name__)


def _is_deterministic_contract_error(exc: Exception) -> bool:
    err_str = str(exc).lower()
    return 'schema' in err_str or 'contract' in err_str or 'type' in err_str or 'validation' in err_str


async def run_passive_scanning(
    args: Any,
    config: Any,
    ctx: PipelineContext,
    *,
    stage_input: StageInput | None = None,
) -> StageOutput:
    """Stage 7: Run passive scanning with iterative feedback loop and validation."""
    from src.analysis.response._core.response_analysis._classification import (
        build_mutation_strategy_coverage,
        build_response_classification_summary,
    )
    from src.pipeline.services.pipeline_helpers import compute_detection_coverage

    if stage_input is None:
        stage_input = build_stage_input_from_context("passive_scan", config, ctx)

    analysis_stage_started = time.monotonic()
    max_iteration_limit = max(1, int(config.analysis.get("max_iteration_limit", 3)))
    feedback_limit = max(1, int(config.analysis.get("finding_feedback_limit", 30)))

    # Mid-Stage Resilience: Recover state from previous deltas
    seen_finding_keys: set[str] = set()
    feedback_urls: set[str] = set(ctx.deep_analysis_urls)
    iteration_offset = 0
    iteration_details: list[dict[str, Any]] = []

    if stage_input.previous_deltas:
        logger.info("Recovering iterative analysis state from %d deltas", len(stage_input.previous_deltas))
        for delta_payload in stage_input.previous_deltas:
            # Reconstruct iteration details and seen keys to skip ahead
            meta = delta_payload.get("metadata", {})
            if meta.get("type") == "iteration_complete":
                iteration_offset = max(iteration_offset, int(meta.get("iteration", 0)))
                iteration_details.append(meta.get("details", {}))
                round_findings = delta_payload.get("delta", {}).get("reportable_findings", [])
                for f in round_findings:
                    seen_finding_keys.add(finding_identity(f))
                # Restore feedback URLs for the next round
                round_feedback = delta_payload.get("delta", {}).get("feedback_urls", [])
                feedback_urls.update(round_feedback)

    total_passive_attempts = 0
    deterministic_contract_failures = 0
    last_passive_error = ""

    state_delta: dict[str, Any] = {
        "analysis_results": dict(ctx.analysis_results),
        "validation_runtime_inputs": dict(ctx.validation_runtime_inputs),
        "merged_findings": list(ctx.merged_findings),
        "reportable_findings": list(ctx.reportable_findings),
        "executed_iterations": iteration_offset,
        "passive_scan_ok": False,
        "validation_ok": False,
        "validation_summary": {},
        "iterative_stop_reason": "",
    }

    try:
        # Resume from next iteration
        for iteration in range(iteration_offset + 1, max_iteration_limit + 1):
            emit_progress(
                "passive_scan",
                f"Running passive analysis checks (round {iteration}/{max_iteration_limit})",
                89,
                processed=iteration,
                total=max_iteration_limit,
                stage_percent=int((iteration / max_iteration_limit) * 100),
            )
            # ... rest of loop logic ...
            state_delta["executed_iterations"] = iteration
            iteration_started = time.monotonic()
            passive_scan_retries = 2
            state_delta["passive_scan_ok"] = False
            iteration_deterministic_error = False
            iteration_passive_attempts = 0
            for attempt in range(1, passive_scan_retries + 1):
                total_passive_attempts += 1
                iteration_passive_attempts += 1
                try:
                    (
                        analysis_results,
                        validation_runtime_inputs,
                    ) = await asyncio.to_thread(
                        run_passive_scanners,
                        ctx.live_hosts,
                        ctx.urls,
                        set(feedback_urls),
                        config,
                        ctx.output_store.cache_root / "response_cache.json",
                        ctx.selected_priority_items,
                    )
                    state_delta["analysis_results"] = analysis_results
                    state_delta["analysis_results"]["behavior_analysis_layer"] = (
                        annotate_behavior_history(
                            ctx.previous_run,
                            state_delta["analysis_results"].get("behavior_analysis_layer", []),
                        )
                    )
                    state_delta["analysis_results"].update(ctx.service_results)
                    validate_detection_payload(dict(state_delta["analysis_results"]))
                    state_delta["validation_runtime_inputs"] = validation_runtime_inputs
                    state_delta["passive_scan_ok"] = True
                    break
                except (TypeError, ValueError, RuntimeError) as exc:
                    last_passive_error = str(exc)
                    deterministic_error = _is_deterministic_contract_error(exc)
                    if deterministic_error:
                        deterministic_contract_failures += 1
                        iteration_deterministic_error = True
                    logger.warning(
                        "Passive scanner attempt %d failed (iteration %d): %s",
                        attempt,
                        iteration,
                        exc,
                    )
                    if deterministic_error:
                        logger.error(
                            "Passive scanners hit deterministic contract failure in iteration %d; not retrying: %s",
                            iteration,
                            exc,
                        )
                    if deterministic_error or attempt == passive_scan_retries:
                        logger.error(
                            "Passive scanners failed after %d retries in iteration %d, using partial results",
                            attempt,
                            iteration,
                        )
                        state_delta["analysis_results"] = {}
                        state_delta["validation_runtime_inputs"] = {
                            "urls": [],
                            "responses": [],
                        }
                        break


            state_delta["merged_findings"] = annotate_finding_decisions(
                annotate_finding_history(
                    ctx.previous_run,
                    merge_findings(
                        state_delta["analysis_results"],
                        ctx.selected_priority_items,
                        ctx.target_profile,
                        config.mode,
                    ),
                )
            )
            state_delta["merged_findings"] = apply_lifecycle(state_delta["merged_findings"])
            validate_analysis_payload({"findings": state_delta["merged_findings"]})
            state_delta["reportable_findings"] = filter_reportable_findings(
                state_delta["merged_findings"]
            )
            validate_decision_payload({"findings": state_delta["reportable_findings"]})

            try:
                state_delta["validation_summary"] = await asyncio.to_thread(
                    execute_validation_runtime,
                    state_delta["analysis_results"],
                    ctx.ranked_priority_urls,
                    config.extensions,
                    config.mode,
                    state_delta["validation_runtime_inputs"],
                )
                state_delta["validation_ok"] = True
            except Exception as exc:
                logger.warning("Inline validation runtime failed in passive scan: %s", exc)
                state_delta["validation_summary"] = {
                    "results": {},
                    "errors": [str(exc)],
                    "settings": {},
                    "metric": {},
                    "metrics": {},
                }
                state_delta["validation_ok"] = False

            round_keys = {finding_identity(item) for item in state_delta["reportable_findings"]}
            new_keys = round_keys - seen_finding_keys
            seen_finding_keys.update(round_keys)

            iteration_duration = round(time.monotonic() - iteration_started, 2)
            high_confidence_count = sum(
                1
                for f in state_delta["reportable_findings"]
                if float(f.get("confidence", 0)) >= 0.7
            )
            medium_confidence_count = sum(
                1
                for f in state_delta["reportable_findings"]
                if 0.5 <= float(f.get("confidence", 0)) < 0.7
            )
            low_confidence_count = sum(
                1 for f in state_delta["reportable_findings"] if float(f.get("confidence", 0)) < 0.5
            )
            avg_confidence = round(
                sum(float(f.get("confidence", 0)) for f in state_delta["reportable_findings"])
                / max(len(state_delta["reportable_findings"]), 1),
                3,
            )
            attack_chain_count = sum(
                1
                for f in state_delta["reportable_findings"]
                if f.get("evidence", {}).get("attack_chain")
            )
            critical_findings_count = sum(
                1
                for f in state_delta["reportable_findings"]
                if str(f.get("severity", "")).lower() == "critical"
            )
            iteration_details.append(
                {
                    "iteration": iteration,
                    "duration_seconds": iteration_duration,
                    "total_findings": len(state_delta["reportable_findings"]),
                    "new_findings": len(new_keys),
                    "high_confidence": high_confidence_count,
                    "medium_confidence": medium_confidence_count,
                    "low_confidence": low_confidence_count,
                    "avg_confidence": avg_confidence,
                    "attack_chain_findings": attack_chain_count,
                    "critical_findings": critical_findings_count,
                    "feedback_urls_count": len(feedback_urls),
                    "passive_scan_ok": state_delta["passive_scan_ok"],
                    "validation_ok": state_delta["validation_ok"],
                    "passive_scan_attempts": iteration_passive_attempts,
                    "deterministic_contract_error": iteration_deterministic_error,
                }
            )

            if iteration > 1 and not new_keys:
                state_delta["iterative_stop_reason"] = "no_new_findings"
                break

            if iteration > 2:
                if len(iteration_details) >= 3:
                    prev_avg: float = float(iteration_details[-2].get("avg_confidence", 0))
                    prev_new: int = int(iteration_details[-2].get("new_findings", 0))
                    if prev_avg > 0 and avg_confidence < prev_avg * 0.85 and len(new_keys) < 2:
                        state_delta["iterative_stop_reason"] = "quality_degradation"
                        break
                    if prev_new == 0 and len(new_keys) == 0:
                        state_delta["iterative_stop_reason"] = "convergence_reached"
                        break

            if iteration < max_iteration_limit:
                new_feedback_urls = extract_feedback_urls(
                    state_delta["reportable_findings"], new_keys
                )
                if not new_feedback_urls:
                    state_delta["iterative_stop_reason"] = "no_feedback_urls"
                    break
                feedback_urls.update(sorted(new_feedback_urls)[:feedback_limit])

    except (TypeError, ValueError, AttributeError, RuntimeError) as exc:
        logger.error("Stage 'passive_scan' failed: %s", exc)
        ctx.mark_stage_failed("passive_scan", str(exc))
        duration = round(time.monotonic() - analysis_stage_started, 2)
        return StageOutput(
            stage_name="passive_scan",
            outcome=StageOutcome.FAILED,
            duration_seconds=duration,
            error=str(exc),
            metrics={
                "status": "error",
                "error": str(exc),
                "iterations": state_delta["executed_iterations"],
                "attempts": total_passive_attempts,
                "deterministic_contract_failures": deterministic_contract_failures,
            },
            state_delta=state_delta,
        )

    # Post-analysis summary (only runs on success)
    detection_coverage = compute_detection_coverage(
        state_delta["analysis_results"], state_delta["reportable_findings"]
    )
    response_classification = build_response_classification_summary(
        state_delta["reportable_findings"]
    )
    mutation_strategy_coverage = build_mutation_strategy_coverage(
        state_delta["reportable_findings"]
    )

    analysis_duration = round(time.monotonic() - analysis_stage_started, 2)
    analysis_status = "ok" if state_delta["passive_scan_ok"] else "warning"
    if deterministic_contract_failures > 0:
        analysis_status = "warning" if state_delta["passive_scan_ok"] else "error"

    return StageOutput(
        stage_name="passive_scan",
        outcome=StageOutcome.COMPLETED,
        duration_seconds=analysis_duration,
        metrics={
            "passive_scan": {
                "status": analysis_status,
                "duration_seconds": analysis_duration,
                "iterations": state_delta["executed_iterations"],
                "max_iteration_limit": max_iteration_limit,
                "stop_reason": state_delta["iterative_stop_reason"],
                "passive_scan_ok": state_delta["passive_scan_ok"],
                "validation_ok": state_delta["validation_ok"],
                "attempts": total_passive_attempts,
                "deterministic_contract_failures": deterministic_contract_failures,
                "last_error": last_passive_error,
                "detection_coverage": detection_coverage,
                "iteration_details": iteration_details,
            },
            "analysis": {
                "status": analysis_status,
                "duration_seconds": analysis_duration,
                "iterations": state_delta["executed_iterations"],
                "max_iteration_limit": max_iteration_limit,
                "stop_reason": state_delta["iterative_stop_reason"],
                "detection_coverage": detection_coverage,
                "response_classification": response_classification,
                "mutation_strategy_coverage": mutation_strategy_coverage,
                "deterministic_contract_failures": deterministic_contract_failures,
            },
        },
        state_delta=state_delta,
    )
