"""Remediation Verification Scanner.

Phase 9.1: Closed-loop exploit remediation re-scanning.
"""

from __future__ import annotations

import logging
from typing import Any

from src.dashboard.fastapi.routers.targets import is_target_owned_by_tenant
from src.execution.exploiters.aeve import AEVE, VerificationStatus

logger = logging.getLogger(__name__)


class RemediationScanner:
    """Orchestrates re-testing of remediated findings using AEVE proof bundles."""

    def __init__(self, use_wasm_sandbox: bool = True):
        self.aeve = AEVE(use_wasm_sandbox=use_wasm_sandbox)

    async def verify_remediation(
        self,
        finding: dict[str, Any],
        redis_client: Any = None,
        tenant_id: str | None = None,
    ) -> dict[str, Any]:
        """Verify if a finding has been successfully remediated.

        Runs the AEVE verifier on the finding. If AEVE fails to verify the vulnerability,
        it is considered remediated. Otherwise, it is still active/unremediated.
        """
        finding_id = finding.get("id") or finding.get("finding_id")
        target_name = finding.get("target_name") or finding.get("target") or ""

        # Enforce tenant isolation
        if tenant_id and not is_target_owned_by_tenant(target_name, tenant_id):
            raise PermissionError("Access denied: target does not belong to this tenant.")

        # Check and enforce adaptive 72h cooldown in Redis
        cooldown_key = f"remediation:cooldown:{tenant_id or 'default'}:{finding_id}"
        if redis_client:
            try:
                # Read cooldown from Redis
                cooldown_active = redis_client.execute_command("EXISTS", cooldown_key)
                if cooldown_active:
                    ttl = redis_client.execute_command("TTL", cooldown_key)
                    # Convert bytes to int if needed
                    if isinstance(ttl, bytes):
                        ttl = int(ttl.decode("utf-8"))
                    elif ttl is not None:
                        ttl = int(ttl)
                    else:
                        ttl = 259200
                    return {
                        "status": "cooldown",
                        "message": f"Remediation verification is on cooldown. Try again in {ttl} seconds.",
                        "cooldown_remaining_seconds": ttl,
                    }
            except Exception as exc:
                logger.warning("Failed to check remediation cooldown in Redis: %s", exc)

        # Run AEVE verification
        logger.info("RemediationScanner: Re-testing finding %s via AEVE", finding_id)
        verified_result = await self.aeve.verify_finding(finding)

        status = verified_result.get("verification_status")
        is_still_vulnerable = status == VerificationStatus.VERIFIED_TP.value

        # Update lifecycle/status of the finding
        if is_still_vulnerable:
            outcome = "failed"
            finding["lifecycle_state"] = "UNREMEDIATED"
            finding["status"] = "active"
            message = "Remediation verification failed. The vulnerability is still exploitable."
        else:
            outcome = "success"
            finding["lifecycle_state"] = "REMEDIATED"
            finding["status"] = "remediated"
            message = "Remediation verification succeeded. The vulnerability has been resolved."

        # Save cooldown in Redis (default 72h = 259200 seconds)
        if redis_client:
            try:
                redis_client.execute_command("SET", cooldown_key, "active")
                redis_client.execute_command("EXPIRE", cooldown_key, 259200)
            except Exception as exc:
                logger.warning("Failed to set remediation cooldown in Redis: %s", exc)

        return {
            "status": outcome,
            "message": message,
            "finding_id": finding_id,
            "verification_status": status,
            "still_vulnerable": is_still_vulnerable,
            "finding": finding,
        }
