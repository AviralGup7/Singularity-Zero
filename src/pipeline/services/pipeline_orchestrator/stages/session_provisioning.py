"""Authentication session provisioning stage."""

from __future__ import annotations

from typing import Any

from src.core.contracts.pipeline_runtime import StageInput, StageOutcome, StageOutput
from src.core.contracts.scan_session import (
    ScanSession,
    SessionCredential,
    SessionProvisioningOutput,
)
from src.core.logging.trace_logging import get_pipeline_logger

logger = get_pipeline_logger(__name__)


class SessionProvisioningStage:
    @staticmethod
    def get_stage_definition() -> Any:
        from src.pipeline.services.pipeline_orchestrator._graph_dsl import (
            AlwaysTrue,
            StageNode,
        )
        return StageNode(
            name="session_provisioning",
            needs=(),
            when=AlwaysTrue(),
            weight=1,
            timeout=120,
        )

    @staticmethod
    async def execute(stage_input: StageInput) -> StageOutput:
        auth_config = getattr(stage_input.pipeline, "auth", None)
        if not auth_config:
            return StageOutput(
                stage_name="session_provisioning",
                outcome=StageOutcome.SKIPPED,
                duration_seconds=0.0,
                state_delta={"session_provisioning_skipped": True},
                reason="no_auth_config",
            )
        scan_id = getattr(stage_input.pipeline, "run_id", "default")
        scan_session = ScanSession(scan_id=scan_id, base_url=getattr(auth_config, "base_url", "") or "")
        provisioned: list[str] = []
        providers = getattr(auth_config, "providers", []) or []
        for provider in providers:
            cred = SessionCredential(
                type=str(getattr(provider, "type", "session_cookie")),
                name=str(getattr(provider, "name", "default")),
                value=scan_session.encrypt_value(str(getattr(provider, "value", ""))),
                scope=frozenset(getattr(provider, "scope", []) or []),
                expires_at=getattr(provider, "expires_at", None),
                metadata=dict(getattr(provider, "metadata", {}) or {}),
            )
            scan_session.add_credential(cred)
            provisioned.append(cred.name)
        output = SessionProvisioningOutput(
            session_id=scan_id,
            username=getattr(auth_config, "username", None),
            auth_method=str(getattr(auth_config, "method", "session_cookie")),
            success=bool(provisioned),
            error=None if provisioned else "no_providers",
            credentials_provisioned=tuple(provisioned),
        )
        state_delta: dict[str, Any] = {
            "scan_session": scan_session.to_state_dict(),
            "scan_session_id": scan_id,
            "session_provisioned": bool(provisioned),
            "session_provisioning_output": output.__dict__,
        }
        return StageOutput(
            stage_name="session_provisioning",
            outcome=StageOutcome.COMPLETED if provisioned else StageOutcome.SKIPPED,
            duration_seconds=0.0,
            state_delta=state_delta,
            reason="auth_configured" if provisioned else "no_providers",
        )
