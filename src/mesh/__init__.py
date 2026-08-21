"""Cluster membership / bloom sync facade."""

from __future__ import annotations

from typing import Any


def bloom_synchronizer_cls() -> Any:
    from src.infrastructure.health.bloom_mesh import BloomMeshSynchronizer

    return BloomMeshSynchronizer


def mesh_status() -> dict[str, Any]:
    try:
        cls = bloom_synchronizer_cls()
    except Exception as exc:  # noqa: BLE001
        return {"status": "disabled", "reason": str(exc)}
    return {"status": "available", "synchronizer": cls.__name__}


__all__ = ["bloom_synchronizer_cls", "mesh_status"]
