"""Async wrappers for scanner subprocesses.

Scanner CLIs (Trivy, Checkov, Grype, Semgrep, Gitleaks) commonly return
exit code 1 when they *found issues*. Codes >= 2 or < 0 are treated as
tool failures so a crashed scan cannot be reported as a clean COMPLETED.
"""

from __future__ import annotations

import asyncio
import subprocess
import time
import uuid
from collections.abc import Sequence
from pathlib import Path
from typing import Any


def is_scanner_crash(returncode: int | None) -> bool:
    """True when the CLI failed to run, as opposed to reporting findings."""
    if returncode is None:
        return True
    return returncode < 0 or returncode >= 2


async def run_scanner(
    cmd: Sequence[str],
    *,
    timeout: int,
    cwd: str | Path | None = None,
    stage_name: str = "tool_scan",
    tenant_id: str = "default",
    budget_enforcer: Any | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run authorized scanner subprocess under formal contract of intent."""
    from src.decision.authorization import ExecutionAuthorizer
    from src.decision.hunt_budget import HuntBudget, HuntBudgetEnforcer
    from src.decision.models import (
        ActionSpec,
        ExecutionRequest,
        ResourceLimits,
        ScopeToken,
        TargetSpec,
    )
    from src.execution.request_executor import ExecutionRequestWorker

    if budget_enforcer is None:
        from src.core.frontier.authority_runtime import get_current_hunt_budget

        budget_enforcer = get_current_hunt_budget()
    enforcer = budget_enforcer or HuntBudgetEnforcer(HuntBudget(max_requests=1000), label=stage_name)
    authorizer = ExecutionAuthorizer(budget_enforcer=enforcer)
    worker = ExecutionRequestWorker(authorizer=authorizer)

    tool_name = cmd[0] if cmd else "scanner"
    action = ActionSpec(
        action_id=f"act_{uuid.uuid4().hex[:8]}",
        action_type="subprocess_scan",
        tool_or_detector=tool_name,
        payload=(("cmd", tuple(cmd)), ("timeout", timeout)),
    )

    req = ExecutionRequest(
        request_id=f"req_{uuid.uuid4().hex[:12]}",
        tenant_id=tenant_id,
        target=TargetSpec(host="localhost", path=str(cwd or "/")),
        stage=stage_name,
        actions=(action,),
        resource_limits=ResourceLimits(timeout_seconds=float(timeout)),
        scope_token=ScopeToken(scope_hash="local_tool_scope", allowed_domains=("localhost",)),
        deadline=time.time() + timeout + 10.0,
    )

    ticket = authorizer.authorize(req)

    def _run_tool_action(act: ActionSpec, r: ExecutionRequest) -> dict[str, Any]:
        proc = subprocess.run(  # noqa: S603
            list(cmd),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            cwd=str(cwd) if cwd is not None else None,
        )
        return {
            "returncode": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
        }

    worker.register_handler("subprocess_scan", _run_tool_action)

    def _execute_worker() -> subprocess.CompletedProcess[str]:
        res = worker.execute(ticket)
        if res.outcome == "REJECTED":
            raise RuntimeError(f"Tool execution authorization rejected: {res.error}")
        artifacts = dict(res.artifacts)
        action_res = artifacts.get(f"action_{action.action_id}", {})
        return subprocess.CompletedProcess(
            args=list(cmd),
            returncode=action_res.get("returncode", 1),
            stdout=action_res.get("stdout", ""),
            stderr=action_res.get("stderr", res.error),
        )

    return await asyncio.to_thread(_execute_worker)

