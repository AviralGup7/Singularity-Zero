"""SBOM diff stage."""

from __future__ import annotations

import json
import time
from typing import Any

from src.core.contracts.pipeline_runtime import StageInput, StageOutcome, StageOutput
from src.core.logging.trace_logging import get_pipeline_logger
from src.core.models.stage_result import PipelineContext
from src.pipeline.runner_support import emit_progress
from src.pipeline.services.pipeline_helpers import build_stage_input_from_context

logger = get_pipeline_logger(__name__)


def _component_key(component: dict[str, Any]) -> str:
    return component.get("purl") or component.get("name", "")


async def run_sbom_diff_stage(
    args: Any,
    config: Any,
    ctx: PipelineContext,
    scope_interceptor: Any = None,
    *,
    stage_input: StageInput | None = None,
) -> StageOutput:
    """Stage: Diff current SBOM against previous SBOM."""
    if stage_input is None:
        stage_input = build_stage_input_from_context("sbom_diff", config, ctx)

    stage_started = time.monotonic()
    previous_sbom = getattr(ctx.result, "previous_sbom", None) or {}
    if not previous_sbom:
        ctx.mark_stage_skipped("sbom_diff", reason="no_previous_sbom")
        duration = round(time.monotonic() - stage_started, 2)
        return StageOutput(
            stage_name="sbom_diff",
            outcome=StageOutcome.SKIPPED,
            duration_seconds=duration,
            metrics={"status": "skipped", "reason": "no_previous_sbom"},
            state_delta={},
        )

    sbom = getattr(ctx.result, "sbom", None) or {}
    if not sbom:
        ctx.mark_stage_skipped("sbom_diff", reason="no_current_sbom")
        duration = round(time.monotonic() - stage_started, 2)
        return StageOutput(
            stage_name="sbom_diff",
            outcome=StageOutcome.SKIPPED,
            duration_seconds=duration,
            metrics={"status": "skipped", "reason": "no_current_sbom"},
            state_delta={},
        )

    emit_progress("sbom_diff", "Diffing current SBOM against previous", 50)

    try:
        prev_components = {_component_key(c): c for c in previous_sbom.get("components", []) if isinstance(c, dict)}
        curr_components = {_component_key(c): c for c in sbom.get("components", []) if isinstance(c, dict)}

        new_components = [curr_components[k] for k in curr_components if k not in prev_components]
        removed_components = [prev_components[k] for k in prev_components if k not in curr_components]
        changed_components = []
        for key in curr_components:
            if key in prev_components and curr_components[key] != prev_components[key]:
                changed_components.append(
                    {
                        "previous": prev_components[key],
                        "current": curr_components[key],
                    }
                )

        sbom_diff = {
            "new_components_count": len(new_components),
            "removed_components_count": len(removed_components),
            "changed_components_count": len(changed_components),
            "new_components": new_components,
            "removed_components": removed_components,
            "changed_components": changed_components,
        }

        findings: list[dict[str, Any]] = []
        for comp in new_components:
            findings.append(
                {
                    "type": "sbom_new_component",
                    "component": comp,
                    "evidence": {"change": "added"},
                }
            )
        for comp in removed_components:
            findings.append(
                {
                    "type": "sbom_removed_component",
                    "component": comp,
                    "evidence": {"change": "removed"},
                }
            )
        for change in changed_components:
            findings.append(
                {
                    "type": "sbom_changed_component",
                    "previous": change.get("previous"),
                    "current": change.get("current"),
                    "evidence": {"change": "updated"},
                }
            )

        ctx.mark_stage_complete("sbom_diff")
        duration = round(time.monotonic() - stage_started, 2)
        state_delta = {
            "sbom_diff": sbom_diff,
            "new_components": new_components,
            "removed_components": removed_components,
            "changed_components": changed_components,
        }
        return StageOutput(
            stage_name="sbom_diff",
            outcome=StageOutcome.COMPLETED,
            duration_seconds=duration,
            metrics={
                "status": "ok",
                "new_components": len(new_components),
                "removed_components": len(removed_components),
                "changed_components": len(changed_components),
            },
            state_delta=state_delta,
            findings=tuple(findings),
        )

    except Exception as exc:
        logger.error("SBOM diff failed: %s", exc)
        ctx.mark_stage_failed("sbom_diff", str(exc))
        duration = round(time.monotonic() - stage_started, 2)
        return StageOutput(
            stage_name="sbom_diff",
            outcome=StageOutcome.FAILED,
            duration_seconds=duration,
            error=str(exc),
            metrics={"status": "error", "error": str(exc)},
            state_delta={},
        )
