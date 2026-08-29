"""Per-stage I30 ticket + I29 sandbox admission (F-004).

Live path: reserve HuntBudget ticket (scope+reservation+revision+command)
then ProcessSandbox metadata-guard, then the stage runner. Unit tests
without ``_authority_runtime`` skip the ticket (no dual writer).
"""

from __future__ import annotations

import hashlib
import logging
from typing import Any
from urllib.parse import urlparse

from src.core.contracts.pipeline_runtime import StageOutcome, StageOutput
from src.decision.authorization import ScopeAuthorizationError
from src.decision.models import ExecutionRequest, ScopeToken, TargetSpec

logger = logging.getLogger(__name__)


class StageAdmissionError(RuntimeError):
    """Stage was refused a ticket or failed the sandbox egress check."""


def _target_host(config: Any, ctx: Any) -> str:
    raw = str(getattr(config, "target_name", "") or "").strip()
    if not raw and ctx is not None:
        entries = getattr(getattr(ctx, "result", ctx), "scope_entries", None) or []
        if entries:
            raw = str(entries[0]).strip()
    if "://" in raw:
        parsed = urlparse(raw)
        raw = parsed.hostname or raw
    return raw.split(":")[0].strip().lower() or "localhost"


def _allowed_domains(config: Any, ctx: Any, host: str) -> tuple[str, ...]:
    domains: list[str] = []
    if host and host not in {"localhost", "127.0.0.1"}:
        domains.append(host)
    entries = getattr(getattr(ctx, "result", ctx), "scope_entries", None) or []
    for entry in entries:
        raw = str(entry or "").strip().lower()
        if "://" in raw:
            parsed = urlparse(raw)
            raw = (parsed.hostname or raw).lower()
        raw = raw.split(":")[0].strip()
        if raw and raw not in {"localhost", "127.0.0.1"}:
            domains.append(raw)
    return tuple(dict.fromkeys(domains))


def build_stage_request(ctx: Any, stage_name: str, config: Any) -> ExecutionRequest:
    host = _target_host(config, ctx)
    run_id = str(getattr(ctx, "run_id", "") or "run")
    allowed = _allowed_domains(config, ctx, host)
    scope_hash = hashlib.sha256(f"{run_id}:{','.join(allowed)}".encode()).hexdigest()[:32]
    tenant = (
        str(getattr(config, "tenant_id", "") or getattr(ctx, "tenant_id", "") or "default").strip()
        or "default"
    )
    return ExecutionRequest(
        request_id=f"stage:{run_id}:{stage_name}",
        tenant_id=tenant,
        target=TargetSpec(host=host),
        stage=stage_name,
        scope_token=ScopeToken(scope_hash=scope_hash, allowed_domains=allowed),
        correlation_id=run_id,
        execution_id=f"{run_id}:{stage_name}",
    )


def failed_stage_output(
    stage_name: str,
    *,
    error: str,
    reason: str = "",
    duration_seconds: float = 0.0,
    retry_count: int = 0,
) -> StageOutput:
    return StageOutput(
        stage_name=stage_name,
        outcome=StageOutcome.FAILED,
        duration_seconds=duration_seconds,
        retry_count=retry_count,
        reason=reason or "stage_failed",
        error=error,
        metrics={"status": "failed", "error": error, "reason": reason or "stage_failed"},
    )


def admit_stage(
    orchestrator: Any,
    ctx: Any,
    stage_name: str,
    config: Any,
) -> Any | None:
    """Return an AuthorizedExecutionTicket, or None when no authority is attached.

    Raises StageAdmissionError when authority is attached but the ticket
    cannot be issued (exhausted budget, fenced placement, open breaker).
    """
    runtime = getattr(orchestrator, "_authority_runtime", None)
    if runtime is None:
        return None
    from src.pipeline.authority_bootstrap import resolve_execution_authorizer
    from src.sandbox.process_sandbox import ProcessSandbox

    authorizer = resolve_execution_authorizer(
        ctx=ctx, budget_enforcer=getattr(runtime, "hunt_budget", None)
    )
    request = build_stage_request(ctx, stage_name, config)
    try:
        ticket = authorizer.authorize(request)
    except ScopeAuthorizationError as exc:
        raise StageAdmissionError(f"I30: stage '{stage_name}' refused a ticket: {exc}") from exc
    try:
        consumed = authorizer.consume_ticket(ticket)
    except Exception as exc:
        from src.decision.authorization import TicketAlreadyConsumedError

        if isinstance(exc, TicketAlreadyConsumedError):
            raise StageAdmissionError(f"I30 replay: {exc}") from exc
        raise
    if not consumed:
        raise StageAdmissionError(f"I30: stage '{stage_name}' ticket consume failed before sandbox")
    host = request.target.host
    # Install process-wide I29 filter for in-process httpx/requests (F-004).
    # install_filter_from_scope also enables raw-client hooks so analysis/recon
    # call sites that bypass shared_sessions still enforce the active filter.
    # Subprocess paths still go through ProcessSandbox.check_egress.
    from src.sandbox.egress_context import (
        ensure_process_http_egress_hooks,
        install_filter_from_scope,
    )

    ensure_process_http_egress_hooks()
    scope_entries = getattr(getattr(ctx, "result", ctx), "scope_entries", None)
    filt = install_filter_from_scope(
        scope_token=getattr(request, "scope_token", None),
        scope_entries=scope_entries,
    )
    sandbox = ProcessSandbox(egress_filter=filt)
    try:
        sandbox.check_egress(host)
    except Exception as exc:
        raise StageAdmissionError(
            f"I29: stage '{stage_name}' sandbox refused egress to {host}: {exc}"
        ) from exc
    try:
        ctx.execution_ticket = ticket
        ctx.command_id = getattr(ticket, "command_id", "")
        ctx.egress_filter = filt
    except Exception:
        logger.debug("Could not stamp execution_ticket on ctx", exc_info=True)
    return ticket


def consume_stage_ticket(orchestrator: Any, ticket: Any | None) -> bool:
    if ticket is None:
        return True
    runtime = getattr(orchestrator, "_authority_runtime", None)
    authorizer = getattr(runtime, "authorizer", None) if runtime is not None else None
    if authorizer is None or not hasattr(authorizer, "consume_ticket"):
        return True
    try:
        return bool(authorizer.consume_ticket(ticket))
    except Exception as exc:
        from src.decision.authorization import TicketAlreadyConsumedError

        if isinstance(exc, TicketAlreadyConsumedError):
            return True
        raise


__all__ = [
    "StageAdmissionError",
    "admit_stage",
    "build_stage_request",
    "consume_stage_ticket",
    "failed_stage_output",
]
