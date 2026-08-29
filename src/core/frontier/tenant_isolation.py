"""I38: tenant isolation enforcement.

Presentation/middleware gating is not allowed to be the only tenant check.
Call ``assert_tenant_scope`` on any path that reads or mutates a tenant-bound
resource. Empty tenant on either side is fail-closed.
"""

from __future__ import annotations


class TenantIsolationError(PermissionError):
    """Cross-tenant access or missing tenant binding (I38)."""


def assert_tenant_scope(*, resource_tenant: str, actor_tenant: str) -> None:
    """Refuse when actor and resource tenants differ or either is empty."""
    actor = str(actor_tenant or "").strip()
    resource = str(resource_tenant or "").strip()
    if not actor or not resource:
        raise TenantIsolationError("I38: tenant binding required on actor and resource")
    if actor != resource:
        raise TenantIsolationError(
            f"I38: actor tenant {actor!r} cannot access resource tenant {resource!r}"
        )


__all__ = ["TenantIsolationError", "assert_tenant_scope"]
