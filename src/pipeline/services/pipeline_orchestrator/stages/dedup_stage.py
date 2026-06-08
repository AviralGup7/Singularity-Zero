"""Dedup stage: separates new findings from duplicates against submitted baseline."""

from __future__ import annotations

from typing import Any

from src.analysis.bug_bounty.dedup import FindingDedup


async def run_dedup_stage(
    args: Any,
    config: Any,
    ctx: Any,
    *,
    stage_input: Any | None = None,
) -> Any:
    from src.core.contracts.pipeline_runtime import StageOutcome, StageOutput
    from src.pipeline.services.pipeline_helpers import build_stage_input_from_context

    started = __import__("time").time()
    if stage_input is None:
        stage_input = build_stage_input_from_context("dedup_stage", config, ctx)

    store_path = getattr(config, "submitted_findings_store", "") or ""
    if not store_path:
        return StageOutput(
            stage_name="dedup_stage",
            outcome=StageOutcome.SKIPPED,
            duration_seconds=round(__import__("time").time() - started, 2),
            metrics={"reason": "no_submitted_findings_store_configured"},
            state_delta={
                "new_findings": list(getattr(ctx.result, "reportable_findings", []) or []),
                "duplicate_findings": [],
            },
        )

    dedup = FindingDedup(store_path)
    findings = list(getattr(ctx.result, "reportable_findings", []) or [])
    new_findings: list[dict[str, Any]] = []
    duplicate_findings: list[dict[str, Any]] = []
    for finding in findings:
        is_dup, report_id = dedup.is_duplicate(finding)
        entry = dict(finding)
        entry["dedup_report_id"] = report_id
        if is_dup:
            duplicate_findings.append(entry)
        else:
            new_findings.append(entry)

    return StageOutput(
        stage_name="dedup_stage",
        outcome=StageOutcome.COMPLETED,
        duration_seconds=round(__import__("time").time() - started, 2),
        metrics={
            "total_findings": len(findings),
            "new_findings": len(new_findings),
            "duplicate_findings": len(duplicate_findings),
        },
        state_delta={
            "new_findings": new_findings,
            "duplicate_findings": duplicate_findings,
        },
    )
