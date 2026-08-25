"""Immutable, versioned scoring and adaptation policy for cognitive learning feedback."""

from __future__ import annotations

import hashlib
import hmac
import time
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class VersionedPolicy:
    """Immutable versioned policy snapshot with provenance and lineage tracking."""

    policy_id: str
    version: str
    parent_policy_id: str = ""
    created_at: float = field(default_factory=time.time)
    effective_from: float = field(default_factory=time.time)
    expires_at: float = 0.0
    confidence_score: float = 1.0
    status: str = "ACTIVE"  # "ACTIVE", "CANARY", "SHADOW", "REVOKED", "ROLLED_BACK"
    signature: str = ""
    target_boosts: tuple[tuple[str, float], ...] = ()
    target_suppressions: tuple[tuple[str, float], ...] = ()
    plugin_overrides: tuple[tuple[str, bool], ...] = ()
    threshold_deltas: tuple[tuple[str, float], ...] = ()
    nuclei_adaptive_tags: tuple[tuple[str, Any], ...] = ()
    provenance: tuple[tuple[str, Any], ...] = ()
    schema_version: int = 1

    def compute_signature(self, secret: str = "cstp-policy-signer-v1") -> str:
        payload = f"{self.policy_id}:{self.version}:{self.parent_policy_id}:{self.confidence_score:.3f}:{self.created_at:.3f}".encode()
        return hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "version": self.version,
            "parent_policy_id": self.parent_policy_id,
            "created_at": self.created_at,
            "effective_from": self.effective_from,
            "expires_at": self.expires_at,
            "confidence_score": self.confidence_score,
            "status": self.status,
            "signature": self.signature,
            "target_boosts": dict(self.target_boosts),
            "target_suppressions": dict(self.target_suppressions),
            "plugin_overrides": dict(self.plugin_overrides),
            "threshold_deltas": dict(self.threshold_deltas),
            "nuclei_adaptive_tags": dict(self.nuclei_adaptive_tags),
            "provenance": dict(self.provenance),
            "schema_version": self.schema_version,
        }

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> VersionedPolicy:
        tb = data.get("target_boosts") or {}
        ts = data.get("target_suppressions") or {}
        po = data.get("plugin_overrides") or {}
        td = data.get("threshold_deltas") or {}
        nat = data.get("nuclei_adaptive_tags") or {}
        prov = data.get("provenance") or {}

        pol_id = str(data.get("policy_id") or f"pol_{uuid.uuid4().hex[:8]}")
        ver = str(data.get("version", "1.0.0"))
        parent_id = str(data.get("parent_policy_id", ""))
        created = float(data.get("created_at", time.time()))
        eff_from = float(data.get("effective_from", created))
        exp_at = float(data.get("expires_at", 0.0))
        conf = float(data.get("confidence_score", 1.0))
        status = str(data.get("status", "ACTIVE"))
        sig = str(data.get("signature", ""))
        schema_v = int(data.get("schema_version", 1))

        pol = cls(
            policy_id=pol_id,
            version=ver,
            parent_policy_id=parent_id,
            created_at=created,
            effective_from=eff_from,
            expires_at=exp_at,
            confidence_score=conf,
            status=status,
            signature=sig,
            target_boosts=tuple(tb.items()) if isinstance(tb, Mapping) else (),
            target_suppressions=tuple(ts.items()) if isinstance(ts, Mapping) else (),
            plugin_overrides=tuple(po.items()) if isinstance(po, Mapping) else (),
            threshold_deltas=tuple(td.items()) if isinstance(td, Mapping) else (),
            nuclei_adaptive_tags=tuple(nat.items()) if isinstance(nat, Mapping) else (),
            provenance=tuple(prov.items()) if isinstance(prov, Mapping) else (),
            schema_version=schema_v,
        )
        if not pol.signature:
            object.__setattr__(pol, "signature", pol.compute_signature())
        return pol

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> VersionedPolicy:
        return cls.from_mapping(data)


__all__ = ["VersionedPolicy"]
