"""Frontier import path for policy governance (atlas F-033).

Canonical implementation lives in :mod:`src.learning.policy_governance`.
"""

from __future__ import annotations

try:
    from src.learning.policy_governance import PolicyGovernanceGate
except Exception:  # pragma: no cover - learning optional in some test shards

    class PolicyGovernanceGate:  # type: ignore[no-redef]
        """Minimal stub when learning package is unavailable."""

        def allow(self, *_args: object, **_kwargs: object) -> bool:
            return True


__all__ = ["PolicyGovernanceGate"]
