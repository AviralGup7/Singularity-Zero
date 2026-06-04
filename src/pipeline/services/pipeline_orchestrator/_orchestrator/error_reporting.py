"""Stage error collection and fatal-failure reporting for pipeline runs.

Provides utilities to gather and summarise fatal stage failures from the
pipeline context for use in exit-code resolution and post-run reporting.
"""

from __future__ import annotations

from src.core.models.stage_result import PipelineContext, StageStatus
from .fatal_detection import metrics_indicate_fatal_failure


def collect_failed_stages(ctx: PipelineContext) -> list[tuple[str, str]]:
    """Gather all fatal stage failures for reporting.

    Returns a list of ``(stage_name, reason)`` pairs for every stage that
    finished with a ``FAILED`` status and is judged fatal by
    :func:`metrics_indicate_fatal_failure`. The fatal-detection helper
    applies a conservative safety-net rule: any failed status is treated
    as fatal unless the metrics explicitly mark it non-fatal.

    Args:
        ctx: The current pipeline context holding stage status and metrics.

    Returns:
        Ordered list of ``(stage_name, human_readable_reason)`` tuples.
    """
    failed_stages: list[tuple[str, str]] = []
    for stage_name, status in ctx.result.stage_status.items():
        if status != StageStatus.FAILED.value:
            continue
        metrics = ctx.result.module_metrics.get(stage_name, {})
        if not isinstance(metrics, dict) or not metrics_indicate_fatal_failure(metrics):
            continue
        reason: str = (
            metrics.get("failure_reason")
            or metrics.get("reason")
            or metrics.get("error")
            or f"Stage {stage_name} failed"
        )
        failed_stages.append((stage_name, str(reason)))
    return failed_stages
