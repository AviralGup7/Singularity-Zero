"""Neural-Mesh execution entry-point.

Drives the :class:`ActorScheduler` to execute the pipeline graph
with per-node readiness polling, conditional gating, and priority
ordering.  Replaces the legacy tier-batched runner that lived here
prior to the actor-scheduler refactor.

Concrete helpers live in the ``_orchestrator`` sub-package:

* Fatal failure detection → ``_orchestrator.fatal_detection``
* Recon output validation  → ``_orchestrator.recon_validator``
* Stage error collection   → ``_orchestrator.error_reporting``
* Stage retry execution    → ``_orchestrator.retry``
"""

from __future__ import annotations

import argparse
from typing import Any

from src.core.logging.trace_logging import get_pipeline_logger
from src.core.models.stage_result import PipelineContext, StageStatus
from src.pipeline.services.ci import (
    ExitConditionPolicy,
    FindingsRule,
    PolicyEvaluation,
    SeverityThresholds,
    evaluate_policy,
    load_policy,
)

from ._orchestrator import validate_recon_outputs
from .actor_scheduler import ActorScheduler
from .graph_builder import build_pipeline_graph

logger = get_pipeline_logger(__name__)


# Exit-code taxonomy (kept stable across versions):
#   0  pass             — run completed, no policy violation
#   1  error            — legacy/unclassified failure
#   2  policy_violation — findings exceeded declared policy thresholds
#   3  infra_failure    — operational failure (network, missing tool, fatal recon)
#   4  partial          — at least one non-fatal stage failed but the run
#                          produced a usable report
#  130 interrupted      — SIGINT / SIGTERM
def _load_incremental_baseline(checkpoint_mgr: Any) -> list[dict[str, Any]]:
    """Load reportable_findings from the last successful checkpoint, if available."""
    if checkpoint_mgr is None:
        return []
    try:
        state = checkpoint_mgr.load()
        if state is None:
            return []
        findings = (
            state.stage_outputs.get("reportable_findings")
            if hasattr(state, "stage_outputs") and isinstance(state.stage_outputs, dict)
            else None
        )
        if not findings:
            findings = (
                state.context_snapshot.get("result", {}).get("reportable_findings", [])
                if hasattr(state, "context_snapshot") and isinstance(state.context_snapshot, dict)
                else []
            )
        if not isinstance(findings, list):
            return []
        return [f for f in findings if isinstance(f, dict)]
    except Exception:  # noqa: BLE001
        return []


def _fingerprint_finding(finding: dict[str, Any]) -> str:
    import hashlib

    tool = str(finding.get("tool") or finding.get("source") or "unknown").strip().lower()
    target = (
        str(
            finding.get("target_url")
            or finding.get("affected_url")
            or finding.get("url")
            or "unknown"
        )
        .strip()
        .lower()
    )
    vuln_type = (
        str(
            finding.get("vuln_type") or finding.get("category") or finding.get("title") or "unknown"
        )
        .strip()
        .lower()
    )
    affected = str(finding.get("affected_url") or finding.get("url") or "unknown").strip().lower()
    raw = "|".join([tool, target, vuln_type, affected])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _diff_findings_against_baseline(
    current_findings: list[dict[str, Any]],
    baseline_findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    baseline_fps = {_fingerprint_finding(f) for f in baseline_findings}
    return [f for f in current_findings if _fingerprint_finding(f) not in baseline_fps]


EXIT_OK = 0
EXIT_POLICY_VIOLATION = 2
EXIT_INFRA_FAILURE = 3
EXIT_PARTIAL = 4


def _resolve_branch(args: argparse.Namespace, config: Any) -> str:
    """Best-effort current-branch lookup for policy gating.

    The CLI is the canonical source (``--branch``) but we also accept
    the conventional ``GITHUB_REF_NAME`` / ``CI_COMMIT_REF_NAME``
    environment variables so dashboards and CI jobs work out of the
    box.
    """
    import os

    explicit = getattr(args, "branch", None) or getattr(config, "branch", None)
    if explicit:
        return str(explicit)
    for env in ("CYBER_BRANCH", "GITHUB_REF_NAME", "CI_COMMIT_REF_NAME", "BRANCH_NAME"):
        value = os.environ.get(env)
        if value:
            return value
    return ""


def _resolve_policy(args: argparse.Namespace, config: Any) -> ExitConditionPolicy:
    """Load the policy from ``--policy`` (CLI), ``config.ci.policy``,
    or fall back to :data:`DEFAULT_POLICY`.
    """
    policy_path = getattr(args, "policy", None)
    if policy_path is None:
        ci_cfg = getattr(config, "ci", None) or {}
        if hasattr(config, "to_dict") and isinstance(ci_cfg, dict):
            policy_path = ci_cfg.get("policy")
        elif isinstance(ci_cfg, dict):
            policy_path = ci_cfg.get("policy")
    try:
        return load_policy(policy_path)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Failed to load policy %r (%s); using DEFAULT_POLICY", policy_path, exc)
        return ExitConditionPolicy()


def _failed_stages(ctx: PipelineContext) -> dict[str, dict[str, Any]]:
    failed: dict[str, dict[str, Any]] = {}
    for stage_name, status in ctx.result.stage_status.items():
        if status == StageStatus.FAILED.value:
            metrics = ctx.result.module_metrics.get(stage_name) or {}
            failed[stage_name] = metrics if isinstance(metrics, dict) else {"status": "failed"}
    return failed


async def execute_remaining_stages(
    orchestrator: Any,
    *,
    remaining_stages: list[str],
    stage_methods: dict[str, Any],
    args: argparse.Namespace,
    config: Any,
    ctx: PipelineContext,
    scope_interceptor: Any,
    nuclei_available: bool,
    checkpoint_mgr: Any,
    handled_by_parallel: set[str],
    stage_checkpoint_guard: Any,
    progress_emitter: Any,
    error_emitter: Any,
) -> int | None:
    """Execute the pipeline using the ActorScheduler.

    ``handled_by_parallel`` is accepted for backward compatibility with
    callers that previously separated "tier stages" from "parallel
    stages".  In the actor model every stage is dispatched uniformly
    by the readiness loop, so the set is no longer populated by this
    function — callers can still inspect it for telemetry if they
    wish.
    """
    graph = build_pipeline_graph(
        stage_methods=stage_methods, tool_status=getattr(config, "tool_status", None)
    )
    logger.info(
        "Neural-Mesh ActorScheduler: greedy readiness loop "
        "(%d nodes, %d remaining, %d pre-completed)",
        len(graph.nodes),
        len(remaining_stages),
        len(checkpoint_mgr.completed_stages) if hasattr(checkpoint_mgr, "completed_stages") else 0,
    )

    completed_stages: set[str] = set()
    if hasattr(checkpoint_mgr, "completed_stages"):
        completed_stages.update(checkpoint_mgr.completed_stages)
    else:
        # If the checkpoint manager doesn't have a completed_stages attribute,
        # try to recover it from the checkpoint state
        try:
            state = checkpoint_mgr.load() if hasattr(checkpoint_mgr, "load") else None
            if state is not None and hasattr(state, "stage_status") and state.stage_status:
                for stage_name, status in state.stage_status.items():
                    if status == "completed":
                        completed_stages.add(stage_name)
        except Exception:  # noqa: BLE001, S110
            pass

    # The recon validator is a post-completion hook on ``urls``.  It
    # sets ``recon_validation=FAILED`` in the context when the URL
    # collection completed but produced no discoverable URLs.  The
    # exit-code resolver consults that flag to decide whether to
    # surface a non-zero exit for a dead-scope run.
    post_hooks: dict[str, Any] = {
        "urls": lambda _ctx: validate_recon_outputs(ctx),
    }

    scheduler = ActorScheduler(
        graph=graph,
        stage_methods=stage_methods,
        ctx=ctx,
        remaining_stages=list(remaining_stages),
        completed_stages=completed_stages,
        orchestrator=orchestrator,
        args=args,
        config=config,
        scope_interceptor=scope_interceptor,
        nuclei_available=nuclei_available,
        checkpoint_mgr=checkpoint_mgr,
        stage_checkpoint_guard=stage_checkpoint_guard,
        progress_emitter=progress_emitter,
        error_emitter=error_emitter,
        post_completion_hooks=post_hooks,
    )

    outcome = await scheduler.run()

    # Recon validator: the legacy code returned ``1`` from this
    # function when ``recon_validation`` was FAILED.  The actor
    # scheduler does not itself abort on this condition (it only
    # aborts on critical stage failures), so the exit-code policy is
    # enforced here, before the orchestrator's own resolver runs.
    if (
        outcome.exit_code is None
        and ctx.result.stage_status.get("recon_validation") == StageStatus.FAILED.value
    ):
        if not getattr(args, "dry_run", False):
            logger.error("Recon validation failed: no discoverable URLs found.")
            error_emitter(
                "recon_validation",
                "Recon validation failed: no discoverable URLs found.",
            )
            return EXIT_INFRA_FAILURE
        ctx.result.stage_status["recon_validation"] = StageStatus.COMPLETED.value

    return outcome.exit_code


def resolve_pipeline_exit_code(
    orchestrator: Any,
    *,
    ctx: PipelineContext,
    config: Any,
    started_at: float,
    progress_emitter: Any,
    args: argparse.Namespace | None = None,
) -> int:
    """Compute the final exit code for the pipeline run.

    The new taxonomy:

    * ``0``  — pass
    * ``2``  — findings exceed the policy thresholds
    * ``3``  — operational failure (fatal recon, network, etc.)
    * ``4``  — partial (some non-fatal stages failed, possibly because a
              recon stage ran in degraded mode — see ``RECON_DEGRADED``)
    * ``130``— SIGINT/SIGTERM

    Degraded mode:
        When a stage listed in ``policy.infra.degraded_stages`` fails
        but a sibling/downstream stage still surfaced actionable data
        (e.g. ``urls`` succeeded via certificate transparency after
        ``subdomains`` failed), the failure is recorded as
        ``degraded=True`` in the stage metrics, a ``RECON_DEGRADED``
        event is emitted, and the run is downgraded to ``partial``
        (exit 4) instead of ``infra_failure`` (exit 3).  Bug-bounty
        hunters want findings from every reachable stage, even when
        upstream recon is incomplete.
    """
    import time

    duration = time.time() - started_at
    findings_count = len(ctx.result.reportable_findings)

    if getattr(ctx.result, "cancel_requested", False):
        progress_emitter("shutdown", "Pipeline cancelled by user", 100, status="stopped")
        return 130

    args = args if args is not None else getattr(orchestrator, "_last_args", None)
    policy = _resolve_policy(args, config) if args is not None else ExitConditionPolicy()

    if args is not None and getattr(args, "ci_fail_on_severity", None):
        cli_threshold = str(args.ci_fail_on_severity).strip().lower()
        try:
            severity_order = ("critical", "high", "medium", "low", "info")
            idx = severity_order.index(cli_threshold)
            thresholds_kwargs = {}
            for i, sev in enumerate(severity_order):
                thresholds_kwargs[sev] = 0 if i >= idx else 999999
            policy = ExitConditionPolicy(
                findings=FindingsRule(thresholds=SeverityThresholds(**thresholds_kwargs)),
                infra=policy.infra,
                on_failure=policy.on_failure,
                ci=policy.ci,
            )
        except Exception:  # noqa: BLE001, S110
            pass
    branch = _resolve_branch(args, config) if args is not None else ""

    evaluation: PolicyEvaluation
    findings_for_policy = list(getattr(ctx.result, "reportable_findings", []) or [])
    if args is not None and getattr(args, "incremental", False):
        checkpoint_mgr_ref = (
            getattr(orchestrator, "_checkpoint_mgr", None) if orchestrator else None
        )
        baseline = _load_incremental_baseline(checkpoint_mgr_ref)
        if baseline:
            baseline_fps = {_fingerprint_finding(f) for f in baseline}
            current_total = list(findings_for_policy)
            findings_for_policy = [
                f for f in current_total if _fingerprint_finding(f) not in baseline_fps
            ]
            logger.info(
                "Incremental mode: diffed %d current findings against %d baseline; %d new findings for policy evaluation.",
                len(current_total),
                len(baseline),
                len(findings_for_policy),
            )
        metrics = ctx.result.module_metrics.get("recon_validation", {})
        if metrics.get("fatal", True):
            # Degraded-mode escape hatch: if the recon validator
            # flagged a dead URL scope but ``subdomains`` still
            # surfaced actionable targets, treat the validation as a
            # warning and continue in degraded mode.  The
            # ``subdomain_takeover`` stage and any user-supplied
            # ``active_scan`` consumers can still work on the
            # discovered subdomains.
            salvaged_subdomains = ctx.result.stage_status.get(
                "subdomains"
            ) == StageStatus.COMPLETED.value and bool(ctx.result.subdomains)
            if salvaged_subdomains:
                if isinstance(metrics, dict):
                    metrics["degraded"] = True
                    metrics["degraded_salvaged_by"] = "subdomains"
                    metrics["fatal"] = False
                progress_emitter(
                    "recon_validation",
                    "RECON_DEGRADED: no discoverable URLs but subdomains "
                    "surfaced actionable targets; continuing in degraded mode.",
                    100,
                    status="warning",
                    event_trigger="recon_degraded",
                    degraded=True,
                    salvaged_by="subdomains",
                )
                logger.warning(
                    "RECON_DEGRADED: recon_validation failed (no URLs) but "
                    "%d subdomain(s) are available; continuing in degraded mode.",
                    len(ctx.result.subdomains),
                )
                try:
                    from src.core.events import EventType, get_event_bus

                    emit = (
                        getattr(orchestrator, "_emit_event", None)
                        if orchestrator is not None
                        else None
                    )
                    payload = {
                        "stage": "recon_validation",
                        "salvaged_by": "subdomains",
                        "subdomain_count": len(ctx.result.subdomains),
                    }
                    if callable(emit):
                        emit(
                            EventType.RECON_DEGRADED,
                            source="recon_validator",
                            data=payload,
                        )
                    else:
                        get_event_bus().emit(
                            EventType.RECON_DEGRADED,
                            source="recon_validator",
                            data=payload,
                        )
                except Exception as exc:  # noqa: BLE001
                    logger.debug("Failed to emit RECON_DEGRADED event: %s", exc)
            else:
                evaluation = PolicyEvaluation(
                    exit_code=EXIT_INFRA_FAILURE,
                    outcome="infra_failure",
                    failed_stages=("recon_validation",),
                    branch=branch,
                    policy_snapshot=policy.to_dict(),
                )
                _emit_policy_result(orchestrator, evaluation)
                progress_emitter(
                    "shutdown",
                    "Pipeline aborted: recon validation failed (no discoverable URLs).",
                    100,
                    status="failed",
                )
                return evaluation.exit_code

    else:
        # Degraded-mode salvage for non-incremental runs:
        # Apply even when not in incremental mode so a dead URL scope
        # can be salvaged by subdomains in any run.
        metrics_rv = ctx.result.module_metrics.get("recon_validation", {})
        if metrics_rv.get("fatal", True) and metrics_rv:
            salvaged_subdomains = ctx.result.stage_status.get(
                "subdomains"
            ) == StageStatus.COMPLETED.value and bool(ctx.result.subdomains)
            if salvaged_subdomains and isinstance(metrics_rv, dict):
                metrics_rv["degraded"] = True
                metrics_rv["degraded_salvaged_by"] = "subdomains"
                metrics_rv["fatal"] = False
                logger.warning(
                    "RECON_DEGRADED: recon_validation failed but subdomains salvaged the run."
                )

    # Apply degraded-mode detection before the hard infra-failure gate
    # so a salvaged degraded-stage failure doesn't trigger
    # ``infra_failure``.  This consults the policy's
    # ``degraded_stages`` set rather than the legacy hard-coded
    # ``{"subdomains", "live_hosts", "urls"}`` triple.
    _apply_recon_degradation(orchestrator, ctx, policy, progress_emitter)

    for stage_name in sorted(policy.infra.fatal_stages):
        if ctx.result.stage_status.get(stage_name) == StageStatus.FAILED.value:
            metrics = ctx.result.module_metrics.get(stage_name, {})
            if metrics.get("fatal", False) and not metrics.get("degraded", False):
                evaluation = PolicyEvaluation(
                    exit_code=EXIT_INFRA_FAILURE,
                    outcome="infra_failure",
                    failed_stages=(stage_name,),
                    branch=branch,
                    policy_snapshot=policy.to_dict(),
                )
                _emit_policy_result(orchestrator, evaluation)
                progress_emitter(
                    "shutdown",
                    f"Pipeline aborted: fatal stage '{stage_name}' failed.",
                    100,
                    status="failed",
                )
                return evaluation.exit_code

    evaluation = evaluate_policy(
        policy,
        findings=findings_for_policy,
        failed_stages=_failed_stages(ctx),
        branch=branch,
    )

    # Backwards compatibility: legacy code returned 1 for any non-zero
    # exit; callers that haven't been updated to handle the new codes
    # can opt in to the legacy mapping via ``--legacy-exit-codes``.
    if args is not None and getattr(args, "legacy_exit_codes", False):
        if evaluation.exit_code in (EXIT_POLICY_VIOLATION, EXIT_INFRA_FAILURE, EXIT_PARTIAL):
            evaluation = PolicyEvaluation(
                exit_code=1,
                outcome=evaluation.outcome,
                counts=evaluation.counts,
                violations=evaluation.violations,
                failed_stages=evaluation.failed_stages,
                partial=evaluation.partial,
                branch=evaluation.branch,
                policy_snapshot=evaluation.policy_snapshot,
                degraded_stages=evaluation.degraded_stages,
            )

    _emit_policy_result(orchestrator, evaluation)
    _persist_policy_evaluation(ctx, evaluation)

    if evaluation.exit_code == 0:
        progress_emitter(
            "shutdown",
            f"Pipeline execution complete. Found {findings_count} finding(s).",
            100,
            status="completed",
            details={
                "duration_seconds": round(duration, 2),
                "findings": findings_count,
                "policy_outcome": evaluation.outcome,
            },
        )
    else:
        progress_emitter(
            "shutdown",
            f"Pipeline finished with policy outcome '{evaluation.outcome}' "
            f"(exit {evaluation.exit_code}).",
            100,
            status="failed",
            details={
                "duration_seconds": round(duration, 2),
                "findings": findings_count,
                "policy_outcome": evaluation.outcome,
                "exit_code": evaluation.exit_code,
            },
        )
    return evaluation.exit_code


# Downstream-stage lookup for degraded-mode salvage detection.
# A failure in ``stage_name`` is considered salvaged when a
# later-listed stage produced non-empty output.  Only stages that
# can independently surface targets without depending on the failed
# stage count as salvagers:
#
#   * ``urls`` can salvage ``subdomains`` because crt.sh and
#     historical URL databases surface URLs without first
#     enumerating subdomains.
#   * ``subdomains`` can salvage ``urls`` because ``subdomain_takeover``
#     and any user-supplied active-scan consumers can still probe
#     the discovered subdomains.
#   * ``live_hosts`` is intentionally NOT a salvager for any other
#     stage — it depends on subdomains as input, so a live-hosts
#     result that depends on subdomains is not a valid salvage.
_RECON_DEGRADED_SALVAGED_BY: dict[str, tuple[str, ...]] = {
    "subdomains": ("urls",),
    "urls": ("subdomains",),
}


def _apply_recon_degradation(
    orchestrator: Any,
    ctx: PipelineContext,
    policy: ExitConditionPolicy,
    progress_emitter: Any,
) -> None:
    """Detect degraded-mode salvage for failed recon stages.

    For each stage in ``policy.infra.degraded_stages`` that ended in
    FAILED status, look for a sibling/downstream stage that produced
    non-empty output.  If one is found, the failure is recorded as
    ``degraded=True`` in the metrics (overriding ``fatal=True``) and a
    ``RECON_DEGRADED`` event is emitted so dashboards and CI
    consumers can show a warning without aborting the run.

    This is what lets ``subdomains`` failure + ``urls`` success (via
    crt.sh or historical data) continue the pipeline in degraded mode
    instead of aborting with ``infra_failure`` (exit 3).
    """
    if not policy.infra.degraded_stages:
        return

    _EventType: Any = None
    _get_event_bus: Any = None
    try:
        from src.core.events import EventType as _EventType
        from src.core.events import get_event_bus as _get_event_bus
    except Exception as exc:  # noqa: BLE001
        logger.debug("EventBus unavailable for RECON_DEGRADED: %s", exc)

    for stage_name in policy.infra.degraded_stages:
        if ctx.result.stage_status.get(stage_name) != StageStatus.FAILED.value:
            continue
        salvaging = _recon_degraded_salvage_stage(ctx, stage_name)
        if salvaging is None:
            continue
        metrics = ctx.result.module_metrics.setdefault(stage_name, {})
        if not isinstance(metrics, dict):
            metrics = {"status": str(metrics)}
            ctx.result.module_metrics[stage_name] = metrics
        metrics["degraded"] = True
        metrics["degraded_salvaged_by"] = salvaging
        metrics["fatal"] = False
        reason = str(metrics.get("failure_reason") or "stage failed")
        logger.warning(
            "RECON_DEGRADED: stage '%s' failed (%s) but '%s' produced "
            "actionable output; continuing in degraded mode.",
            stage_name,
            reason,
            salvaging,
        )
        progress_emitter(
            stage_name,
            f"RECON_DEGRADED: {stage_name} failed but {salvaging} salvaged the run.",
            100,
            status="warning",
            event_trigger="recon_degraded",
            degraded=True,
            salvaged_by=salvaging,
            failure_reason=reason,
        )
        payload = {
            "stage": stage_name,
            "salvaged_by": salvaging,
            "failure_reason": reason,
            "metrics": {k: v for k, v in metrics.items() if k != "retry_metrics"},
        }
        event_type = _EventType
        get_event_bus_ref = _get_event_bus
        if event_type is not None and get_event_bus_ref is not None:
            try:
                emit = (
                    getattr(orchestrator, "_emit_event", None) if orchestrator is not None else None
                )
                if callable(emit):
                    emit(event_type.RECON_DEGRADED, source=f"stage.{stage_name}", data=payload)
                else:
                    get_event_bus_ref().emit(
                        event_type.RECON_DEGRADED, source=f"stage.{stage_name}", data=payload
                    )
            except Exception as exc:  # noqa: BLE001
                logger.debug("Failed to emit RECON_DEGRADED event: %s", exc)


def _recon_degraded_salvage_stage(ctx: PipelineContext, stage_name: str) -> str | None:
    """Return the name of a downstream stage that salvaged ``stage_name``.

    A stage is considered salvaged when:

    * it ran and completed successfully (``stage_status`` is COMPLETED),
      AND
    * it produced a non-empty output (``ctx.subdomains`` or ``ctx.urls``
      contains at least one entry, or its own state attribute is
      non-empty).

    The order of candidates is governed by
    :data:`_RECON_DEGRADED_SALVAGED_BY` so the first matching candidate
    is preferred (e.g. ``urls`` over ``live_hosts`` for ``subdomains``).
    """
    candidates = _RECON_DEGRADED_SALVAGED_BY.get(stage_name, ())
    for candidate in candidates:
        if ctx.result.stage_status.get(candidate) != StageStatus.COMPLETED.value:
            continue
        if not _stage_output_is_non_empty(ctx, candidate):
            continue
        return candidate
    return None


def _stage_output_is_non_empty(ctx: PipelineContext, stage_name: str) -> bool:
    """Return True if the pipeline context holds non-empty output for
    ``stage_name``.

    Falls back to reading the named attribute on ``ctx.result`` so
    arbitrary stage names work without hard-coding each one.
    """
    value = getattr(ctx.result, stage_name, None)
    if value is None:
        return False
    try:
        return len(value) > 0
    except TypeError:
        return bool(value)


def _emit_policy_result(orchestrator: Any, evaluation: PolicyEvaluation) -> None:
    """Emit the INGRESS_POLICY_RESULT event so policy engines can subscribe.

    Falls back to the process-wide event bus when ``orchestrator`` is
    ``None`` or doesn't expose ``_emit_event`` (e.g. in unit tests that
    invoke :func:`resolve_pipeline_exit_code` directly).
    """
    try:
        from src.core.events import EventType, get_event_bus
    except Exception as exc:  # noqa: BLE001
        logger.debug("EventBus unavailable for INGRESS_POLICY_RESULT: %s", exc)
        return
    payload = {"evaluation": evaluation.to_dict()}
    emit = getattr(orchestrator, "_emit_event", None) if orchestrator is not None else None
    if callable(emit):
        try:
            emit(EventType.INGRESS_POLICY_RESULT, source="policy", data=payload)
            return
        except Exception as exc:  # noqa: BLE001
            logger.debug("Orchestrator emit failed: %s; falling back to bus.emit", exc)
    try:
        get_event_bus().emit(EventType.INGRESS_POLICY_RESULT, source="policy", data=payload)
    except Exception as exc:  # noqa: BLE001
        logger.debug("Failed to emit INGRESS_POLICY_RESULT: %s", exc)


def _persist_policy_evaluation(ctx: PipelineContext, evaluation: PolicyEvaluation) -> None:
    """Write the policy evaluation next to the run report for CI consumers."""
    output_store = getattr(ctx, "output_store", None)
    if output_store is None:
        return
    run_dir = getattr(output_store, "run_dir", None)
    if run_dir is None:
        return
    try:
        import json
        from pathlib import Path

        path = Path(run_dir) / "policy_evaluation.json"
        path.write_text(
            json.dumps(evaluation.to_dict(), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
    except OSError as exc:  # noqa: BLE001
        logger.debug("Failed to persist policy_evaluation.json: %s", exc)
