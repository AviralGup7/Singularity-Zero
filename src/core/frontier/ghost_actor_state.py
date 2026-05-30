"""Serializable state representation for Ghost-Actor migration."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from src.core.frontier.marshaller import mesh_marshal, mesh_unmarshal
from src.core.frontier.state import stable_digest


@dataclass
class ActorState:
    """Serializable state for actor migration."""

    actor_id: str
    stage: str
    data: dict[str, Any]
    checkpoint_ts: float
    evacuation_recommended: bool = False
    logic_fn_name: str = ""
    snapshot_format: str = "ghost-actor-snapshot-v3"
    last_wal_id: str | None = None
    migration_id: str = ""
    state_digest: str = ""
    applied_wal_ids: list[str] = field(default_factory=list)
    compaction_budget: dict[str, Any] = field(default_factory=dict)
    serialized_logic_fn: bytes | None = None

    def pack(self) -> bytes:
        """Binary serialization via MessagePack."""
        return mesh_marshal(
            {
                "actor_id": self.actor_id,
                "stage": self.stage,
                "data": self.data,
                "checkpoint_ts": self.checkpoint_ts,
                "evacuation_recommended": self.evacuation_recommended,
                "logic_fn_name": self.logic_fn_name,
                "snapshot_format": self.snapshot_format,
                "last_wal_id": self.last_wal_id,
                "migration_id": self.migration_id,
                "state_digest": self.state_digest or stable_digest(self.data),
                "applied_wal_ids": self.applied_wal_ids,
                "compaction_budget": self.compaction_budget,
                "serialized_logic_fn": self.serialized_logic_fn,
            }
        )

    @classmethod
    def unpack(cls, payload: bytes) -> ActorState:
        """Binary deserialization via MessagePack."""
        data = mesh_unmarshal(payload)
        data.setdefault("snapshot_format", "ghost-actor-snapshot-v1")
        data.setdefault("last_wal_id", None)
        data.setdefault("migration_id", "")
        data.setdefault("state_digest", stable_digest(data.get("data", {})))
        data.setdefault("applied_wal_ids", [])
        data.setdefault("compaction_budget", {})
        data.setdefault("serialized_logic_fn", None)
        valid_keys = {f.name for f in cls.__dataclass_fields__.values()}
        filtered = {k: v for k, v in data.items() if k in valid_keys}
        return cls(**filtered)

    def dehydrate(self) -> bytes:
        """Serialize actor state into a binary format."""
        return self.pack()

    @classmethod
    def rehydrate(cls, payload: Any) -> ActorState:
        """De-serialize actor state from a binary format."""
        if isinstance(payload, cls):
            return payload
        if isinstance(payload, dict):
            payload.setdefault("actor_id", "actor-unknown")
            payload.setdefault("stage", "stage-unknown")
            payload.setdefault("data", {})
            payload.setdefault("checkpoint_ts", 0.0)
            payload.setdefault("evacuation_recommended", False)
            payload.setdefault("logic_fn_name", "")
            payload.setdefault("snapshot_format", "ghost-actor-snapshot-v3")
            payload.setdefault("last_wal_id", None)
            payload.setdefault("migration_id", "")
            payload.setdefault("state_digest", "")
            payload.setdefault("applied_wal_ids", [])
            payload.setdefault("compaction_budget", {})
            payload.setdefault("serialized_logic_fn", None)
            valid_keys = {f.name for f in cls.__dataclass_fields__.values()}
            filtered = {k: v for k, v in payload.items() if k in valid_keys}
            return cls(**filtered)
        if isinstance(payload, bytes):
            return cls.unpack(payload)
        raise TypeError(f"a bytes-like object is required, not {type(payload).__name__}")
