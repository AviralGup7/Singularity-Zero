from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from src.learning.integration import LearningIntegration

logger = logging.getLogger(__name__)


def compute_adaptations(
    integration: LearningIntegration,
    ctx: dict[str, Any],
) -> dict[str, Any]:
    """Compute feedback-driven adaptations before a scan begins.

    Call this at the start of PipelineOrchestrator.run() to apply
    learning from previous runs.
    """
    if not integration.config.enabled:
        return {}

    target = ctx.get("target_name", "")
    mode = ctx.get("mode", "deep")
    lookback = integration.config.feedback.lookback_runs

    adaptations = integration._feedback_engine.compute_adaptations(
        target=target,
        mode=mode,
        lookback_runs=lookback,
    )

    # 🛸 Frontier Upgrade: Nuclei Tag Optimization (Phase 5.1)
    # Extract current adaptive_tags from context to compute optimizations
    nuclei_cfg = ctx.get("nuclei", {})
    current_adaptive_tags = nuclei_cfg.get("adaptive_tags", {})

    if current_adaptive_tags:
        optimized = integration._nuclei_optimizer.optimize_adaptive_tags(
            current_adaptive_tags=current_adaptive_tags,
            lookback_runs=lookback,
        )
        # Only include if there's an actual change detected based on feedback
        if optimized != current_adaptive_tags:
            from src.learning.feedback_loop import ScanAdaptation

            if isinstance(adaptations, ScanAdaptation):
                adaptations.nuclei_adaptive_tags_override = optimized

    return adaptations.to_dict()


def apply_adaptations(
    integration: LearningIntegration,
    ctx: dict[str, Any],
    adaptations: dict[str, Any] | Any,
    config: Any | None = None,
) -> None:
    """Apply computed adaptations to the pipeline context and configuration.

    Modifies ctx and optional config in-place to apply learning-driven changes.
    """
    if not adaptations:
        return

    if not isinstance(adaptations, dict) and hasattr(adaptations, "to_dict"):
        adaptations = adaptations.to_dict()

    # Apply target boosts to scoring config
    if "target_boosts" in adaptations:
        scoring = ctx.setdefault("scoring", {})
        scoring["target_boosts"] = adaptations["target_boosts"]
        scoring["target_suppressions"] = adaptations.get("target_suppressions", {})

    # Apply plugin overrides
    if "plugin_enabled_overrides" in adaptations:
        analysis = ctx.setdefault("analysis", {})
        analysis["plugin_overrides"] = adaptations["plugin_enabled_overrides"]

    if "plugin_intensity_overrides" in adaptations:
        analysis = ctx.setdefault("analysis", {})
        analysis["plugin_intensity"] = adaptations["plugin_intensity_overrides"]

    # Apply threshold adjustments with safe clamping to prevent exceeding valid bounds
    if "threshold_adjustments" in adaptations:
        decision = ctx.setdefault("decision", {})
        decision["threshold_deltas"] = {
            cat: max(-0.15, min(0.15, float(val)))
            for cat, val in adaptations["threshold_adjustments"].items()
        }

    # Apply nuclei template boosts
    if "nuclei_template_boosts" in adaptations:
        ctx["nuclei_template_boosts"] = adaptations["nuclei_template_boosts"]

    # Apply nuclei adaptive tags override
    if "nuclei_adaptive_tags_override" in adaptations:
        nuclei = ctx.setdefault("nuclei", {})
        nuclei["adaptive_tags"] = adaptations["nuclei_adaptive_tags_override"]

    # Queue active exploitation targets
    if "active_exploit_queue" in adaptations:
        ctx["active_exploit_queue"] = adaptations["active_exploit_queue"]

    if config:
        from src.core.config.loader import apply_adaptive_overrides

        # Construct nested adaptive_dict for merge logic
        adaptive_dict: dict[str, Any] = {}

        scoring_overrides = {}
        if "target_boosts" in adaptations:
            scoring_overrides["target_boosts"] = adaptations["target_boosts"]
        if "target_suppressions" in adaptations:
            scoring_overrides["target_suppressions"] = adaptations["target_suppressions"]
        if scoring_overrides:
            adaptive_dict["scoring"] = scoring_overrides

        analysis_overrides = {}
        if "plugin_enabled_overrides" in adaptations:
            analysis_overrides["plugin_overrides"] = adaptations["plugin_enabled_overrides"]
        if "plugin_intensity_overrides" in adaptations:
            analysis_overrides["plugin_intensity"] = adaptations["plugin_intensity_overrides"]
        if analysis_overrides:
            adaptive_dict["analysis"] = analysis_overrides

        decision_overrides = {}
        if "threshold_adjustments" in adaptations:
            decision_overrides["threshold_deltas"] = {
                cat: max(-0.15, min(0.15, float(val)))
                for cat, val in adaptations["threshold_adjustments"].items()
            }
        if decision_overrides:
            adaptive_dict["decision"] = decision_overrides

        nuclei_overrides = {}
        if "nuclei_template_boosts" in adaptations:
            nuclei_overrides["template_boosts"] = adaptations["nuclei_template_boosts"]
        if "nuclei_adaptive_tags_override" in adaptations:
            nuclei_overrides["adaptive_tags"] = adaptations["nuclei_adaptive_tags_override"]
        if nuclei_overrides:
            adaptive_dict["nuclei"] = nuclei_overrides

        if "active_exploit_queue" in adaptations:
            adaptive_dict["active_exploit_queue"] = adaptations["active_exploit_queue"]

        apply_adaptive_overrides(config, adaptive_dict)

    logger.info(
        "Applied learning adaptations: %d target boosts, %d plugin overrides, "
        "%d threshold adjustments, %d exploit targets",
        len(adaptations.get("target_boosts", {})),
        len(adaptations.get("plugin_enabled_overrides", {})),
        len(adaptations.get("threshold_adjustments", {})),
        len(adaptations.get("active_exploit_queue", [])),
    )


async def persist_adaptive_config(
    integration: LearningIntegration,
    ctx: dict[str, Any],
) -> None:
    """Persist the next-run adaptations to config.adaptive.json (Phase 5.2)."""
    output_store = ctx.get("output_store")
    if not output_store:
        return

    # Compute what the adaptations WOULD be for the next run of this same target
    adaptations = compute_adaptations(integration, ctx)
    if adaptations:
        try:
            # We need to reach into the output_store to write the adaptive config
            # The output_store was already enhanced with write_adaptive_config()
            if hasattr(output_store, "write_adaptive_config"):
                output_store.write_adaptive_config(adaptations)

                # Phase 5.2: Write ledger for human audit
                kpis_dict = {}
                try:
                    kpis_obj = integration._metrics.compute_kpis(target=ctx.get("target_name"))
                    kpis_dict = kpis_obj.to_dict()
                except Exception as e:
                    logger.debug("Failed to compute KPIs for adaptive config ledger: %s", e)

                ledger_entry = {
                    "run_id": ctx.get("run_id"),
                    "timestamp": datetime.now(UTC).isoformat(),
                    "adaptations": adaptations,
                    "kpis": kpis_dict,
                }
                output_store.write_json_artifact("config.adaptive.ledger.json", ledger_entry)

                logger.info(
                    "LearningIntegration: Persisted adaptive config for next run of %s",
                    ctx.get("target_name"),
                )
        except Exception as e:
            logger.error("LearningIntegration: Failed to persist adaptive config: %s", e)
