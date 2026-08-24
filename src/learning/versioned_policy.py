"""Immutable, versioned scoring and adaptation policy for cognitive learning feedback."""

from __future__ import annotations

import time
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class VersionedPolicy:
    """Immutable versioned policy snapshot output by Learning Integration."""

    policy_id: str
    version: str
    created_at: float = field(default_factory=time.time)
    target_boosts: tuple[tuple[str, float], ...] = ()
    target_suppressions: tuple[tuple[str, float], ...] = ()
    plugin_overrides: tuple[tuple[str, bool], ...] = ()
    threshold_deltas: tuple[tuple[str, float], ...] = ()
    nuclei_adaptive_tags: tuple[tuple[str, Any], ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "version": self.version,
            "created_at": self.created_at,
            "target_boosts": dict(self.target_boosts),
            "target_suppressions": dict(self.target_suppressions),
            "plugin_overrides": dict(self.plugin_overrides),
            "threshold_deltas": dict(self.threshold_deltas),
            "nuclei_adaptive_tags": dict(self.nuclei_adaptive_tags),
        }

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> VersionedPolicy:
        tb = data.get("target_boosts") or {}
        ts = data.get("target_suppressions") or {}
        po = data.get("plugin_overrides") or {}
        td = data.get("threshold_deltas") or {}
        nat = data.get("nuclei_adaptive_tags") or {}

        return cls(
            policy_id=str(data.get("policy_id") or f"pol_{uuid.uuid4().hex[:8]}"),
            version=str(data.get("version", "1.0.0")),
            created_at=float(data.get("created_at", time.time())),
            target_boosts=tuple(tb.items()) if isinstance(tb, Mapping) else (),
            target_suppressions=tuple(ts.items()) if isinstance(ts, Mapping) else (),
            plugin_overrides=tuple(po.items()) if isinstance(po, Mapping) else (),
            threshold_deltas=tuple(td.items()) if isinstance(td, Mapping) else (),
            nuclei_adaptive_tags=tuple(nat.items()) if isinstance(nat, Mapping) else (),
        )

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> VersionedPolicy:
        return cls.from_mapping(data)


__all__ = ["VersionedPolicy"]
