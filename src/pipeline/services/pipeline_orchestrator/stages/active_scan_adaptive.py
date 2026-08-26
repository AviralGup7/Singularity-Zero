"""Adaptive active scanning stage.

Integrates the AdaptiveScanCoordinator with existing security probes
to provide intelligent, priority-based scanning that boosts correlated
targets when vulnerabilities are found.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any
from urllib.parse import urlparse

from src.core.contracts.pipeline_runtime import StageOutcome, StageOutput
from src.core.logging.trace_logging import get_pipeline_logger
from src.core.models.stage_result import PipelineContext
from src.decision.adaptive_scan import AdaptiveScanCoordinator
from src.decision.hunt_budget import HuntBudgetEnforcer
from src.pipeline.runner_support import emit_progress

from .composite_probe import CompositeActiveProbe
from .probe_registry import (
    _build_response_cache,
    _load_active_probe_functions,
    _normalize_scan_targets,
)
from .probe_runners import _try_probe

logger = get_pipeline_logger(__name__)


async def run_active_scanning_adaptive(
    args: Any,
    config: Any,
    ctx: PipelineContext,
    *,
    probe_loader: Any = _load_active_probe_functions,
) -> StageOutput:
    """Adaptive Stage: Active probing with dynamic prioritization and boosting."""
    stage_started = time.monotonic()

    # Retrieve checkpoint manager and load previous deltas for sub-stage resumption
    checkpoint_mgr = getattr(ctx, "_checkpoint_mgr", None)
    scanned_urls: set[str] = set()
    historical_findings: list[dict[str, Any]] = []

    if checkpoint_mgr and hasattr(checkpoint_mgr, "load_stage_deltas"):
        try:
            previous_deltas = checkpoint_mgr.load_stage_deltas("active_scan")
            for p in previous_deltas:
                delta_dict = p.get("delta") or {}
                scanned_urls.update(delta_dict.get("scanned_targets", []))
                historical_findings.extend(delta_dict.get("findings", []))
            if scanned_urls:
                logger.info(
                    "Resuming active scan: %d targets already scanned, %d findings restored",
                    len(scanned_urls),
                    len(historical_findings),
                )
        except Exception as exc:
            logger.warning("Failed to load active scan previous deltas: %s", exc)

    # 1. Target Preparation
    live_hosts = set(ctx.live_hosts) if ctx.live_hosts else set()
    urls = set(ctx.urls) if ctx.urls else set()

    all_urls = _normalize_scan_targets([*list(urls), *list(live_hosts)])

    # Filter out already scanned URLs
    if scanned_urls:
        all_urls = [u for u in all_urls if u not in scanned_urls]

    if not all_urls:
        logger.info("Adaptive active scan: all targets already scanned, skipping execution")
        duration = round(time.monotonic() - stage_started, 2)
        return StageOutput(
            stage_name="active_scan",
            outcome=StageOutcome.COMPLETED,
            duration_seconds=duration,
            metrics={
                "status": "ok",
                "duration_seconds": duration,
                "targets_total": len(scanned_urls),
                "targets_scanned": len(scanned_urls),
                "findings_count": len(historical_findings),
                "resumed": True,
            },
            state_delta={"active_scan_findings": historical_findings},
        )

    emit_progress("active_scan", f"Starting adaptive scan on {len(all_urls)} targets", 75)

    # 2. Resource Initialization
    try:
        probes = probe_loader()
        response_cache = _build_response_cache()
    except Exception as exc:
        logger.error("Failed to initialize active scan resources: %s", exc)
        return StageOutput(
            stage_name="active_scan",
            outcome=StageOutcome.FAILED,
            duration_seconds=round(time.monotonic() - stage_started, 2),
            error=str(exc),
            state_delta={},
        )

    # 3. Host-Level Probes (Run once per unique host to avoid redundancy)
    unique_hosts = {urlparse(url).netloc for url in all_urls}
    host_targets = [f"https://{host}" for host in unique_hosts if host]
    host_priority_items = [{"url": url} for url in host_targets]

    degraded_probes: list[dict[str, Any]] = []

    analysis_settings = getattr(config, "analysis", {}) if config is not None else {}
    try:
        probe_timeout_seconds = float(analysis_settings.get("active_probe_timeout_seconds", 180))
    except (TypeError, ValueError):
        probe_timeout_seconds = 180.0
    probe_timeout_seconds = max(30.0, probe_timeout_seconds)

    logger.info("Running host-level probes on %d unique hosts", len(unique_hosts))
    host_probe_names = ["cors", "trace", "options", "cloud_metadata"]
    host_tasks = [
        _try_probe(
            "cors",
            probes["cors_preflight_probe"],
            host_priority_items,
            response_cache,
            timeout_seconds=probe_timeout_seconds,
            error_accumulator=degraded_probes,
        ),
        _try_probe(
            "trace",
            probes["trace_method_probe"],
            host_priority_items,
            response_cache,
            timeout_seconds=probe_timeout_seconds,
            error_accumulator=degraded_probes,
        ),
        _try_probe(
            "options",
            probes["options_method_probe"],
            host_priority_items,
            response_cache,
            timeout_seconds=probe_timeout_seconds,
            error_accumulator=degraded_probes,
        ),
        _try_probe(
            "cloud_metadata",
            probes["cloud_metadata_active_probe"],
            host_targets,
            timeout_seconds=probe_timeout_seconds,
            error_accumulator=degraded_probes,
        ),
    ]
    host_results = await asyncio.gather(*host_tasks, return_exceptions=True)

    all_findings: list[dict[str, Any]] = list(historical_findings)
    host_probe_errors: list[str] = []
    for probe_name, r in zip(host_probe_names, host_results, strict=False):
        if isinstance(r, BaseException):
            host_probe_errors.append(f"{probe_name}: {r.__class__.__name__}: {r}")
            logger.error("Host-level probe '%s' failed: %s", probe_name, r)
            continue
        if isinstance(r, tuple):
            _, findings, ok = r
            if ok:
                if findings:
                    all_findings.extend(findings)
            else:
                host_probe_errors.append(f"{probe_name}: probe failed or timed out")

    # 4. Adaptive Endpoint Probes
    batch_size = int(analysis_settings.get("adaptive_batch_size", 20))
    concurrency = int(analysis_settings.get("adaptive_concurrency", 5))

    from src.core.frontier.authority_runtime import get_current_hunt_budget

    budget_enforcer: HuntBudgetEnforcer | None = (
        getattr(ctx, "budget_enforcer", None) or get_current_hunt_budget()
    )
    if budget_enforcer is None:
        try:
            cfg_mapping = (
                config if isinstance(config, dict) else (getattr(config, "__dict__", None) or {})
            )
            budget_enforcer = HuntBudgetEnforcer.from_config(cfg_mapping, label="active_scan")
        except Exception as exc:
            logger.debug("Failed to build HuntBudgetEnforcer from config: %s", exc)

    import uuid

    from src.decision.models import ActionSpec, ExecutionRequest, ScopeToken, TargetSpec
    from src.learning.versioned_policy import VersionedPolicy

    policy: VersionedPolicy | None = getattr(ctx, "_versioned_policy", None)
    if policy is None:
        hf = getattr(ctx, "history_feedback", {}) or {}
        if hf:
            policy = VersionedPolicy.from_mapping(hf)

    from src.pipeline.authority_bootstrap import resolve_execution_authorizer

    authorizer = resolve_execution_authorizer(ctx=ctx, budget_enforcer=budget_enforcer)
    raw_composite_probe = CompositeActiveProbe(
        probes,
        response_cache,
        timeout_seconds=probe_timeout_seconds,
        error_accumulator=degraded_probes,
    )

    stage_ticket = getattr(ctx, "execution_ticket", None)

    async def authorized_probe_fn(url: str) -> list[dict[str, Any]]:
        parsed = urlparse(url)
        host = parsed.hostname or url
        path = parsed.path or "/"
        # F-004: stage admit already reserved+consumed for active_scan. Per-URL
        # authorize() double-reserves HuntBudget and is skipped under a stage
        # ticket. Still enforce I29 egress against the target host.
        if stage_ticket is not None:
            try:
                from src.sandbox.process_sandbox import ProcessSandbox

                ProcessSandbox().check_egress(host)
            except Exception as exc:
                logger.warning("I29 egress refused for %s: %s", url, exc)
                return []
            return await raw_composite_probe(url)

        req = ExecutionRequest(
            request_id=f"req_{uuid.uuid4().hex[:12]}",
            tenant_id=str(getattr(ctx, "tenant_id", "default") or "default"),
            target=TargetSpec(
                host=host, path=path, scheme=parsed.scheme or "https", port=parsed.port or 443
            ),
            stage="active_scan",
            actions=(
                ActionSpec(
                    action_id=f"act_{uuid.uuid4().hex[:8]}",
                    action_type="probe",
                    tool_or_detector="composite_probe",
                ),
            ),
            scope_token=ScopeToken(scope_hash="active_scope", allowed_domains=(host,)),
            deadline=time.time() + probe_timeout_seconds + 30.0,
            policy_version=getattr(policy, "version", "") if policy else "",
        )
        try:
            ticket = authorizer.authorize(req)
            if not authorizer.consume_ticket(ticket):
                logger.warning("Ticket consumption failed for %s", url)
                return []
        except Exception as exc:
            logger.warning("Authorization check failed for %s: %s", url, exc)
            return []

        return await raw_composite_probe(url)

    coordinator = AdaptiveScanCoordinator(
        urls=all_urls,
        probe_fn=authorized_probe_fn,
        batch_size=batch_size,
        concurrency=concurrency,
        boost_on_findings=True,
        budget_enforcer=budget_enforcer,
        policy=policy,
    )

    def save_delta_fn(batch_urls: list[str], batch_findings: list[dict[str, Any]]) -> None:
        if checkpoint_mgr and hasattr(checkpoint_mgr, "save_stage_delta"):
            try:
                checkpoint_mgr.save_stage_delta(
                    "active_scan",
                    delta={
                        "scanned_targets": list(batch_urls),
                        "findings": list(batch_findings),
                    },
                )
            except Exception as exc:
                logger.warning("Failed to save active scan batch delta: %s", exc)

    logger.info("Starting AdaptiveScanCoordinator loop")
    batch_result = await coordinator.run(save_delta_fn=save_delta_fn)

    for result in batch_result.results:
        if result.findings:
            all_findings.extend(result.findings)

    # 5. Result Consolidation
    duration = round(time.monotonic() - stage_started, 2)
    metrics = {
        "status": "ok",
        "duration_seconds": duration,
        "targets_total": len(all_urls),
        "targets_scanned": batch_result.scanned,
        "findings_count": len(all_findings),
        "boosted_count": batch_result.boosted_count,
        "early_terminated": batch_result.early_terminated,
        "adaptive_batches": len(batch_result.results) // batch_size + 1,
        "host_probe_errors_count": len(host_probe_errors),
        "host_probe_errors_sample": host_probe_errors[:5],
        "degraded_probes": degraded_probes,
    }

    emit_progress(
        "active_scan",
        f"Adaptive scan complete: {len(all_findings)} findings on {batch_result.scanned} targets",
        90,
    )

    return StageOutput(
        stage_name="active_scan",
        outcome=StageOutcome.COMPLETED,
        duration_seconds=duration,
        metrics=metrics,
        state_delta={"active_scan_findings": all_findings},
    )
