"""Single lattice: stages × findings × policy × degraded → (JobStatus, exit_code).

CLI ``resolve_pipeline_exit_code`` and dashboard reap both consult this
function so F-018 is one total mapping instead of three overlapping machines.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from src.core.models.stage_status import StageStatus, normalize_stage_status
from src.jobs.status import JobStatus

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_POLICY_VIOLATION = 2
EXIT_INFRA_FAILURE = 3
EXIT_PARTIAL = 4
EXIT_INTERRUPTED = 130


@dataclass(frozen=True, slots=True)
class RunOutcome:
    job_status: JobStatus
    exit_code: int
    reason: str = ""
    degraded_stages: tuple[str, ...] = ()
    failed_stages: tuple[str, ...] = ()


def _stage_items(stage_map: Mapping[str, Any] | None) -> dict[str, StageStatus]:
    if not stage_map:
        return {}
    return {str(name): normalize_stage_status(value) for name, value in stage_map.items()}


def _findings_count(findings: Sequence[Any] | None) -> int:
    if not findings:
        return 0
    return sum(1 for item in findings if item is not None)


def derive_job_and_exit(
    stage_map: Mapping[str, Any] | None,
    findings: Sequence[Any] | None,
    policy: Any | None = None,
    *,
    cancel: bool = False,
    degraded_probes: Sequence[str] = (),
    policy_violated: bool | None = None,
    fatal_stages: Sequence[str] = (),
) -> RunOutcome:
    """Total function from observed machines onto operator job + CI exit.

    Exit codes (stable taxonomy):
      0  — completed; findings absent or under policy
      2  — completed; findings exceeded policy
      3  — infra / fatal stage failure
      4  — partial (DEGRADED or SKIPPED_FAILED, non-fatal)
    130  — cancelled
    """
    if cancel:
        return RunOutcome(job_status=JobStatus.STOPPED, exit_code=EXIT_INTERRUPTED, reason="cancel")

    stages = _stage_items(stage_map)
    failed = tuple(name for name, status in stages.items() if status is StageStatus.FAILED)
    degraded = tuple(
        name
        for name, status in stages.items()
        if status in {StageStatus.DEGRADED, StageStatus.SKIPPED_FAILED}
    )
    if degraded_probes:
        extra = tuple(str(name) for name in degraded_probes if name)
        degraded = tuple(dict.fromkeys((*degraded, *extra)))

    fatal = {str(name) for name in fatal_stages if name}
    fatal_failed = tuple(name for name in failed if not fatal or name in fatal)
    if fatal and fatal_failed:
        return RunOutcome(
            job_status=JobStatus.FAILED,
            exit_code=EXIT_INFRA_FAILURE,
            reason="fatal_stage",
            failed_stages=fatal_failed,
            degraded_stages=degraded,
        )
    if failed and not fatal:
        # Unclassified FAILED stages with no policy.infra.fatal_stages set
        # are infra unless the caller marked them non-fatal via degraded.
        unclassified = tuple(name for name in failed if name not in set(degraded))
        if unclassified:
            return RunOutcome(
                job_status=JobStatus.FAILED,
                exit_code=EXIT_INFRA_FAILURE,
                reason="stage_failed",
                failed_stages=unclassified,
                degraded_stages=degraded,
            )

    violated = policy_violated
    if violated is None and policy is not None and hasattr(policy, "findings"):
        violated = False
    if violated:
        return RunOutcome(
            job_status=JobStatus.COMPLETED,
            exit_code=EXIT_POLICY_VIOLATION,
            reason="policy_violation",
            degraded_stages=degraded,
            failed_stages=failed,
        )

    if degraded:
        return RunOutcome(
            job_status=JobStatus.COMPLETED,
            exit_code=EXIT_PARTIAL,
            reason="degraded",
            degraded_stages=degraded,
            failed_stages=failed,
        )

    count = _findings_count(findings)
    reason = "findings" if count else "clean"
    return RunOutcome(
        job_status=JobStatus.COMPLETED,
        exit_code=EXIT_OK,
        reason=reason,
        degraded_stages=degraded,
        failed_stages=failed,
    )


__all__ = [
    "EXIT_ERROR",
    "EXIT_INFRA_FAILURE",
    "EXIT_INTERRUPTED",
    "EXIT_OK",
    "EXIT_PARTIAL",
    "EXIT_POLICY_VIOLATION",
    "RunOutcome",
    "derive_job_and_exit",
]
