"""Business logic probes coordinator."""

from __future__ import annotations

from typing import Any

from src.analysis.active.business_logic.coupon_stacking import coupon_stacking_probe
from src.analysis.active.business_logic.idempotency_abuse import idempotency_abuse_probe
from src.analysis.active.business_logic.price_manipulation import price_manipulation_probe
from src.analysis.active.business_logic.workflow_bypass import workflow_bypass_probe

__all__ = [
    "coupon_stacking_probe",
    "idempotency_abuse_probe",
    "price_manipulation_probe",
    "run_business_logic_probes",
    "workflow_bypass_probe",
]


def run_business_logic_probes(
    priority_urls: list[dict[str, Any]],
    response_cache: Any | None = None,
    *,
    client: Any = None,
    sandbox_session: Any = None,
    timeout_seconds: float = 5.0,
    limit: int = 20,
) -> list[dict[str, Any]]:
    """Run all business logic probes and return consolidated findings."""
    findings: list[dict[str, Any]] = []

    probes = [
        (price_manipulation_probe, 6),
        (workflow_bypass_probe, 6),
        (coupon_stacking_probe, 4),
        (idempotency_abuse_probe, 4),
    ]

    for probe_fn, per_probe_limit in probes:
        try:
            results = probe_fn(
                priority_urls,
                response_cache=response_cache,
                client=client,
                sandbox_session=sandbox_session,
                limit=per_probe_limit,
                timeout_seconds=timeout_seconds,
            )
            findings.extend(results)
        except Exception as exc:
            import logging
            logging.getLogger(__name__).warning("business logic probe %s failed: %s", probe_fn.__name__, exc)

    return findings
