from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from src.learning.integration import LearningIntegration

logger = logging.getLogger(__name__)


async def run_learning_update(
    integration: LearningIntegration,
    ctx: dict[str, Any],
) -> dict[str, Any]:
    """Execute the full learning cycle after a pipeline run.

    Call this at the end of PipelineOrchestrator.run(), after all
    findings have been collected and reported.
    """
    if not integration.config.enabled:
        return {"status": "disabled"}

    run_id = ctx.get("run_id", "")
    findings = ctx.get("reportable_findings", [])
    result: dict[str, Any] = {"run_id": run_id, "status": "completed"}

    # Phase 1: Record telemetry
    from src.learning.integration._feedback import emit_feedback_events, record_scan_run

    record_scan_run(integration, ctx)
    events_emitted = emit_feedback_events(integration, ctx, findings)
    result["feedback_events_emitted"] = events_emitted

    # Phase 2: Recompute feedback weights
    if run_id:
        updated = integration.store.recompute_feedback_weights(
            run_id, decay_rate=integration.config.feedback.decay_rate
        )
        result["feedback_weights_recomputed"] = updated

    # Phase 3: Update FP patterns
    fp_updated = await integration._fp_tracker.update_from_run(run_id)
    result["fp_patterns_updated"] = fp_updated

    # Phase 4: Calibrate thresholds
    if run_id:
        new_thresholds = integration._threshold_tuner.calibrate(run_id)
        result["thresholds"] = new_thresholds
        result["thresholds_converged"] = integration._threshold_tuner.is_converged

    # Phase 4.5: Active Learning Weight Update
    if run_id:
        try:
            db_findings = integration.store.get_findings_for_run(run_id)
            ctx_findings = ctx.get("reportable_findings", [])

            findings_to_process = []
            seen_ids = set()

            for f in db_findings:
                fid = f.get("finding_id") or f.get("id")
                if fid:
                    seen_ids.add(fid)
                findings_to_process.append(f)

            for f in ctx_findings:
                fid = f.get("finding_id") or f.get("id")
                if fid not in seen_ids:
                    findings_to_process.append(f)

            labeled_findings = []
            for f in findings_to_process:
                evidence_raw = f.get("evidence")
                evidence = {}
                if isinstance(evidence_raw, str):
                    try:
                        evidence = json.loads(evidence_raw)
                    except Exception:
                        evidence = {"raw": evidence_raw}
                elif isinstance(evidence_raw, dict):
                    evidence = evidence_raw

                lifecycle = f.get("lifecycle_state", "")
                decision = f.get("decision", "")

                if decision == "DROP":
                    label = "fp"
                elif lifecycle in ("VALIDATED", "EXPLOITABLE", "REPORTABLE"):
                    label = "tp"
                else:
                    label = "tp"

                labeled_findings.append(
                    {
                        "evidence": evidence,
                        "confidence": float(f.get("confidence", 0.5)),
                        "true_positive_probability": float(
                            f.get("true_positive_probability", f.get("confidence", 0.5))
                        ),
                        "false_positive_probability": float(
                            f.get(
                                "false_positive_probability",
                                1.0 - float(f.get("confidence", 0.5)),
                            )
                        ),
                        "response_status": f.get("response_status"),
                        "feedback": label,
                        "label": label,
                    }
                )

            if labeled_findings:
                updated_weights = integration._threshold_tuner.active_learning_weight_update(
                    labeled_findings
                )
                result["active_learning_weights"] = updated_weights
        except Exception as e:
            logger.error("Failed to run active learning weight update: %s", e, exc_info=True)

    # Phase 5: Record plugin stats
    from src.learning.integration._feedback import record_plugin_stats

    record_plugin_stats(integration, ctx)

    # Phase 6: Compute KPIs
    try:
        kpis = integration._metrics.compute_kpis(target=ctx.get("target_name"))
        result["kpis"] = kpis.to_dict()
    except Exception:
        logger.debug("Failed to compute KPIs", exc_info=True)
        result["kpis"] = {}

    # Phase 7: Persist adaptive config for next run (Phase 5.2)
    await integration._persist_adaptive_config(ctx)

    # Phase 8: Active Learning Retraining
    if run_id and integration._active_learning is not None:
        try:
            retrain_res = integration._active_learning.retrain_from_telemetry(
                str(integration.store.db_path), run_id
            )
            result["active_learning_retrain"] = retrain_res
            logger.info("Active learning retrain outcome: %s", retrain_res)
        except Exception as e:
            logger.error("Failed to execute active learning retraining: %s", e)

    logger.info(
        "Learning update complete for run %s: %d events, %d FP patterns, converged=%s",
        run_id,
        events_emitted,
        fp_updated,
        integration._threshold_tuner.is_converged,
    )

    return result
