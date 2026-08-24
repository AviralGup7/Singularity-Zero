"""Stateless worker and runner for ExecutionRequests.

Executes actions defined in an ExecutionRequest (or AuthorizedExecutionTicket)
deterministically without querying or re-deriving decisions from the Decision subsystem.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from typing import Any

from src.decision.authorization import AuthorizedExecutionTicket
from src.decision.models import (
    ActionSpec,
    ExecutionRequest,
    ExecutionResult,
    Finding,
)

logger = logging.getLogger(__name__)

ActionHandler = Callable[[ActionSpec, ExecutionRequest], dict[str, Any]]


class ExecutionRequestWorker:
    """Stateless worker executing against the formal contract of intent."""

    def __init__(self) -> None:
        self._handlers: dict[str, ActionHandler] = {}
        self._register_default_handlers()

    def register_handler(self, action_type: str, handler: ActionHandler) -> None:
        """Register a custom action execution handler."""
        self._handlers[action_type] = handler

    def _register_default_handlers(self) -> None:
        def _default_probe_handler(action: ActionSpec, req: ExecutionRequest) -> dict[str, Any]:
            return {
                "action_id": action.action_id,
                "tool": action.tool_or_detector,
                "target_url": req.target.url,
                "status": "probed",
            }

        def _default_exploit_handler(action: ActionSpec, req: ExecutionRequest) -> dict[str, Any]:
            return {
                "action_id": action.action_id,
                "tool": action.tool_or_detector,
                "target_url": req.target.url,
                "status": "validated",
            }

        self._handlers["probe"] = _default_probe_handler
        self._handlers["exploit"] = _default_exploit_handler
        self._handlers["nuclei"] = _default_probe_handler
        self._handlers["mutate"] = _default_probe_handler
        self._handlers["fingerprint"] = _default_probe_handler

    def execute(self, request_or_ticket: ExecutionRequest | AuthorizedExecutionTicket) -> ExecutionResult:
        """Execute the request deterministically and return ExecutionResult."""
        request = (
            request_or_ticket.request
            if isinstance(request_or_ticket, AuthorizedExecutionTicket)
            else request_or_ticket
        )

        start_time = time.perf_counter()
        now = time.time()

        # Check deadline before starting
        if request.deadline > 0 and request.deadline < now:
            return ExecutionResult(
                request_id=request.request_id,
                tenant_id=request.tenant_id,
                outcome="TIMED_OUT",
                duration_seconds=0.0,
                error=f"Deadline exceeded before execution start: {request.deadline} < {now}",
            )

        collected_artifacts: dict[str, Any] = {}
        collected_findings: list[Finding] = []
        collected_deltas: dict[str, Any] = {
            "last_scanned_target": request.target.host,
            "stage_executed": request.stage,
        }
        resource_usage: dict[str, Any] = {
            "actions_executed": 0,
            "actions_total": len(request.actions),
        }

        outcome = "COMPLETED"
        error_message = ""

        try:
            for action in request.actions:
                # Check timeout/deadline mid-execution
                if request.deadline > 0 and time.time() > request.deadline:
                    outcome = "TIMED_OUT"
                    error_message = "Execution aborted due to deadline expiration"
                    break

                handler = self._handlers.get(action.action_type, self._handlers.get("probe"))
                if handler:
                    result_data = handler(action, request)
                    collected_artifacts[f"action_{action.action_id}"] = result_data
                    resource_usage["actions_executed"] += 1

                # If action payload suggests a finding, extract it
                payload_dict = dict(action.payload)
                if payload_dict.get("emits_finding"):
                    finding_data = payload_dict.get("finding")
                    if isinstance(finding_data, dict):
                        collected_findings.append(Finding.from_mapping(finding_data))

        except Exception as exc:
            logger.exception("Error executing ExecutionRequest %s", request.request_id)
            outcome = "FAILED"
            error_message = str(exc)

        duration = time.perf_counter() - start_time
        resource_usage["duration_seconds"] = round(duration, 3)

        return ExecutionResult(
            request_id=request.request_id,
            tenant_id=request.tenant_id,
            outcome=outcome,
            duration_seconds=duration,
            findings=tuple(collected_findings),
            artifacts=tuple(collected_artifacts.items()),
            state_deltas=tuple(collected_deltas.items()),
            resource_consumption=tuple(resource_usage.items()),
            error=error_message,
        )


__all__ = [
    "ActionHandler",
    "ExecutionRequestWorker",
]
