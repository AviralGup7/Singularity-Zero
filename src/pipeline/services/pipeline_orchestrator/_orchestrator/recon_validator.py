"""Recon output validation for pipeline runs.

Validates that the recon phases (subdomains → live_hosts → urls) produced
actionable outputs before handing off to active scanning stages.  Absence of
discoverable URLs after a successful recon run is treated as a terminal
failure so the pipeline exits early instead of running active scans against
an empty target set.
"""

from __future__ import annotations

from src.core.logging.trace_logging import get_pipeline_logger
from src.core.models.stage_result import PipelineContext, StageStatus

logger = get_pipeline_logger(__name__)


def validate_recon_outputs(ctx: PipelineContext) -> None:
    """Validate that recon produced actionable outputs.

    Marks ``recon_validation`` as *FAILED* in the pipeline context when the
    ``urls`` stage completed successfully but yielded no discoverable URLs.
    The caller is responsible for checking ``ctx.result.stage_status`` and
    halting the pipeline.
    """
    if not ctx.result.urls and ctx.result.stage_status.get("urls") == StageStatus.COMPLETED.value:
        ctx.result.stage_status["recon_validation"] = StageStatus.FAILED.value
        ctx.result.module_metrics["recon_validation"] = {
            "status": "failed",
            # Bug #N fix: ``collect_failed_stages`` only surfaces the
            # canonical ``failure_reason`` key; we previously wrote to a
            # different key (``reason``) which caused the validator to
            # report a generic "Stage recon_validation failed" string
            # in dashboards instead of the specific recon explanation.
            "failure_reason": "Pipeline finished recon without discoverable URLs.",
            "fatal": True,
        }
        logger.warning(
            "Recon validation failed: urls stage completed but produced no discoverable URLs."
        )
