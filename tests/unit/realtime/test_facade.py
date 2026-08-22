from __future__ import annotations

from src.checkpoint import checkpoint_manager_cls
from src.mesh import mesh_status
from src.realtime import get_broadcaster, get_manager


def test_realtime_facade_is_lazy() -> None:
    assert callable(get_manager)
    assert callable(get_broadcaster)


def test_checkpoint_facade_points_at_core() -> None:
    assert checkpoint_manager_cls().__name__ == "CheckpointManager"


def test_mesh_status_is_serializable() -> None:
    snapshot = mesh_status()
    assert "status" in snapshot
