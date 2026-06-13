"""Authentication session provisioning stage.

Supports three authentication methods:
1. Static credentials (session_cookie, bearer_token) - pre-configured values
2. Auth flow - YAML/JSON multi-step authentication flows via AuthFlowRunner
3. OAuth - OAuth 2.0 authorization code flow via OAuthAuthenticator
"""

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
        scan_session = ScanSession(
            scan_id=scan_id, base_url=getattr(auth_config, "base_url", "") or ""
        )
        provisioned: list[str] = []
        auth_method = str(getattr(auth_config, "method", "session_cookie"))

        if auth_method == "oauth":
            provisioned = await _provision_oauth(auth_config, scan_session, scan_id)
        elif auth_method == "auth_flow":
            provisioned = await _provision_auth_flow(auth_config, scan_session, scan_id)
        else:
            provisioned = _provision_static_credentials(auth_config, scan_session)

        output = SessionProvisioningOutput(
            session_id=scan_id,
            username=getattr(auth_config, "username", None),
            auth_method=auth_method,
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


def _provision_static_credentials(auth_config: Any, scan_session: ScanSession) -> list[str]:
    """Provision static credentials (session_cookie, bearer_token)."""
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
    return provisioned


async def _provision_oauth(auth_config: Any, scan_session: ScanSession, scan_id: str) -> list[str]:
    """Provision OAuth credentials via OAuthAuthenticator."""
    try:
        from src.execution.auth import OAuthAuthenticator
        from src.execution.auth.oauth_authenticator import OAuthConfig

        oauth_config_raw = getattr(auth_config, "oauth_config", None) or {}
        if not oauth_config_raw:
            logger.warning("OAuth method specified but no oauth_config provided")
            return []

        oauth_config = OAuthConfig.from_mapping(oauth_config_raw)
        authenticator = OAuthAuthenticator(oauth_config)
        session_context = await authenticator.authenticate()

        cred = SessionCredential(
            type="bearer_token",
            name="oauth_access_token",
            value=scan_session.encrypt_value(session_context.bearer_token or ""),
            scope=frozenset(["*"]),
            expires_at=session_context.expires_at,
            metadata={
                "user_id": session_context.user_id,
                "obtained_at": session_context.obtained_at,
            },
        )
        scan_session.add_credential(cred)

        if session_context.refresh_token:
            refresh_cred = SessionCredential(
                type="refresh_token",
                name="oauth_refresh_token",
                value=scan_session.encrypt_value(session_context.refresh_token),
                scope=frozenset(["*"]),
                metadata={"user_id": session_context.user_id},
            )
            scan_session.add_credential(refresh_cred)

        return ["oauth_access_token"]
    except Exception as exc:
        logger.error("OAuth provisioning failed: %s", exc)
        return []


async def _provision_auth_flow(
    auth_config: Any, scan_session: ScanSession, scan_id: str
) -> list[str]:
    """Provision credentials via AuthFlowRunner multi-step flow."""
    try:
        from src.execution.auth import AuthFlowRunner, AuthSpec

        auth_spec_raw = getattr(auth_config, "auth_spec", None)
        if not auth_spec_raw:
            logger.warning("auth_flow method specified but no auth_spec provided")
            return []

        auth_spec = (
            AuthSpec.from_mapping(auth_spec_raw)
            if isinstance(auth_spec_raw, dict)
            else auth_spec_raw
        )

        async def _http_client(method: str, url: str, **kwargs: Any) -> Any:
            import httpx

            async with httpx.AsyncClient(verify=False) as client:
                response = await client.request(method, url, **kwargs)
                return {
                    "status_code": response.status_code,
                    "body": response.text,
                    "headers": dict(response.headers),
                }

        runner = AuthFlowRunner(auth_spec, http_client=_http_client)
        session_context = await runner.run()

        cred = SessionCredential(
            type="session_cookie",
            name="auth_flow_session",
            value=scan_session.encrypt_value(str(session_context.cookies)),
            scope=frozenset(["*"]),
            expires_at=session_context.expires_at,
            metadata={
                "user_id": session_context.user_id,
                "obtained_at": session_context.obtained_at,
            },
        )
        scan_session.add_credential(cred)

        if session_context.bearer_token:
            token_cred = SessionCredential(
                type="bearer_token",
                name="auth_flow_token",
                value=scan_session.encrypt_value(session_context.bearer_token),
                scope=frozenset(["*"]),
                expires_at=session_context.expires_at,
            )
            scan_session.add_credential(token_cred)

        return ["auth_flow_session"]
    except Exception as exc:
        logger.error("Auth flow provisioning failed: %s", exc)
        return []
