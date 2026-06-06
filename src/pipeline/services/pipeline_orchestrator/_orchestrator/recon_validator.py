"""Recon output validation for pipeline runs.

Validates that the recon phases (subdomains → live_hosts → urls) produced
actionable outputs before handing off to active scanning stages.  Absence of
discoverable URLs after a successful recon run is treated as a soft warning
by default; the exit-code resolver decides whether to abort or continue in
degraded mode based on the configured :class:`InfraRule` policy.  Marking
``recon_validation`` as *FAILED* is a hint, not a hard kill — operators who
want max findings yield (e.g. bug-bounty hunters) can let
``resolve_pipeline_exit_code`` downgrade the failure to ``partial`` when a
sibling recon stage (``subdomains``) still surfaced actionable targets.
"""

from __future__ import annotations

from src.core.logging.trace_logging import get_pipeline_logger
from src.core.models.stage_result import PipelineContext, StageStatus

logger = get_pipeline_logger(__name__)


def validate_recon_outputs(ctx: PipelineContext) -> None:
    """Validate that recon produced actionable outputs.

    Marks ``recon_validation`` as *FAILED* in the pipeline context when the
    ``urls`` stage completed successfully but yielded no discoverable URLs.
    The caller (``resolve_pipeline_exit_code``) is responsible for checking
    ``ctx.result.stage_status`` and deciding whether to abort
    (``infra_failure``) or continue in degraded mode (``partial``) when
    the policy's ``degraded_stages`` set permits it.
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
