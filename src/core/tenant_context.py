"""Tenant context management using contextvars.

Provides a thread-safe and async-safe context variable to propagate the active
tenant identifier dynamically down to infrastructure and data retrieval layers.
"""

from __future__ import annotations

import contextvars
from collections.abc import Generator
from contextlib import contextmanager

# Context variable to hold the current active tenant ID
_current_tenant: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "current_tenant", default=None
)


class TenantContext:
    """Manages thread-safe and async-safe tenant propagation contexts."""

    @staticmethod
    def get_current_tenant() -> str | None:
        """Retrieve the current active tenant ID from the context.

        Returns:
            The current tenant ID string, or None if no tenant is set.
        """
        return _current_tenant.get()

    @staticmethod
    def set_current_tenant(tenant_id: str | None) -> contextvars.Token[str | None]:
        """Set the current active tenant ID in the context.

        Args:
            tenant_id: The tenant identifier to set.

        Returns:
            A contextvars Token that can be used to reset the context variable.
        """
        return _current_tenant.set(tenant_id)

    @staticmethod
    def reset_current_tenant(token: contextvars.Token[str | None]) -> None:
        """Reset the tenant context back to its previous state using a token.

        Args:
            token: The Token returned by set_current_tenant.
        """
        _current_tenant.reset(token)

    @classmethod
    @contextmanager
    def scope(cls, tenant_id: str | None) -> Generator[None]:
        """Context manager to scope a block of execution to a specific tenant ID.

        Args:
            tenant_id: The tenant identifier to activate for the block duration.
        """
        token = cls.set_current_tenant(tenant_id)
        try:
            yield
        finally:
            cls.reset_current_tenant(token)
