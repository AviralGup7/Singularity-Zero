"""Remediation Verification Scanner.

Phase 9.1: Closed-loop exploit remediation re-scanning.
"""

from __future__ import annotations

import logging
from typing import Any

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
        if tenant_id:
            from src.core.contracts.protocol_registry import get_tenant_isolation_check

            tenant_check = get_tenant_isolation_check()
            if tenant_check is not None and not tenant_check(target_name, tenant_id):
                raise PermissionError("Access denied: target does not belong to this tenant.")

        # Check and enforce adaptive 72h cooldown in Redis
        cooldown_key = f"remediation:cooldown:{tenant_id or 'default'}:{finding_id}"
        cooldown_seconds = 259200  # 72h
        if redis_client:
            try:
                # Read cooldown from Redis. EXISTS returns 1/0; treat 1 as present.
                cooldown_active = redis_client.execute_command("EXISTS", cooldown_key)
                if isinstance(cooldown_active, bytes):
                    cooldown_active = int(cooldown_active.decode("utf-8"))
                if cooldown_active == 1:
                    ttl = redis_client.execute_command("TTL", cooldown_key)
                    # Convert bytes to int if needed
                    if isinstance(ttl, bytes):
                        ttl = int(ttl.decode("utf-8"))
                    elif ttl is None:
                        ttl = cooldown_seconds
                    else:
                        ttl = int(ttl)
                    # Redis TTL semantics:
                    #   -2 = key does not exist (race condition vs EXISTS)
                    #   -1 = key exists but has no TTL set
                    if ttl == -2:
                        # Key vanished between EXISTS and TTL; fall through and
                        # treat as no cooldown.
                        pass
                    else:
                        if ttl == -1:
                            ttl = cooldown_seconds
                        return {
                            "status": "cooldown",
                            "message": (
                                "Remediation verification is on cooldown. "
                                f"Try again in {ttl} seconds."
                            ),
                            "cooldown_remaining_seconds": ttl,
                        }
            except Exception as exc:
                logger.error("Failed to check remediation cooldown in Redis: %s", exc)
                raise RuntimeError(f"Database error during cooldown verification: {exc}") from exc

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

        # Save cooldown in Redis (default 72h = 259200 seconds).
        # Use SET ... NX EX <ttl> so the key and its TTL are set atomically -
        # the previous implementation issued SET + EXPIRE as two commands and
        # could leak a permanent key if the process crashed between them.
        if redis_client:
            try:
                redis_client.execute_command(
                    "SET", cooldown_key, "active", "EX", cooldown_seconds, "NX"
                )
            except Exception as exc:
                logger.error("Failed to set remediation cooldown in Redis: %s", exc)
                raise RuntimeError(f"Database error during cooldown update: {exc}") from exc

        return {
            "status": outcome,
            "message": message,
            "finding_id": finding_id,
            "verification_status": status,
            "still_vulnerable": is_still_vulnerable,
            "finding": finding,
        }
