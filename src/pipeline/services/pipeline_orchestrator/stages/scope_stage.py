"""Scope stage: filters URLs against a bug bounty program scope."""

from __future__ import annotations

from typing import Any

from src.analysis.bug_bounty.scope_parser import ProgramScope, filter_out_of_scope, expand_wildcards, parse_bugcrowd_scope, parse_hackerone_scope


async def run_scope_stage(
    args: Any,
    config: Any,
    ctx: Any,
    *,
    stage_input: Any | None = None,
) -> Any:
    from src.core.contracts.pipeline_runtime import StageInput, StageOutcome, StageOutput
    from src.pipeline.services.pipeline_helpers import build_stage_input_from_context

    started = __import__("time").time()
    if stage_input is None:
        stage_input = build_stage_input_from_context("scope_stage", config, ctx)

    program_scope = getattr(config, "bug_bounty_scope", None)
    if program_scope is None or not str(program_scope).strip():
        return StageOutput(
            stage_name="scope_stage",
            outcome=StageOutcome.SKIPPED,
            duration_seconds=round(__import__("time").time() - started, 2),
            metrics={"reason": "no_program_scope_configured"},
            state_delta={
                "in_scope_urls": [],
                "out_of_scope_urls": [],
                "scope_metadata": {"skipped": True},
            },
        )

    raw_scope_text = str(program_scope)
    scope_format = getattr(config, "bug_bounty_scope_format", "hackerone").strip().lower()
    if scope_format == "bugcrowd":
        scope = parse_bugcrowd_scope(raw_scope_text)
    else:
        scope = parse_hackerone_scope(raw_scope_text)

    target_urls = set(getattr(ctx.result, "urls", set()) or set())
    in_scope = filter_out_of_scope(target_urls, scope)
    out_of_scope = target_urls - in_scope

    return StageOutput(
        stage_name="scope_stage",
        outcome=StageOutcome.COMPLETED,
        duration_seconds=round(__import__("time").time() - started, 2),
        metrics={
            "in_scope_count": len(in_scope),
            "out_of_scope_count": len(out_of_scope),
            "wildcard_patterns": len(scope.wildcard_patterns),
        },
        state_delta={
            "in_scope_urls": sorted(in_scope),
            "out_of_scope_urls": sorted(out_of_scope),
            "scope_metadata": {
                "skipped": False,
                "format": scope_format,
                "wildcard_patterns": scope.wildcard_patterns,
                "target_urls_count": len(scope.target_urls),
                "out_of_scope_count": len(scope.out_of_scope),
                "raw_scope_text": scope.raw_scope_text,
            },
        },
    )
