from __future__ import annotations

from src.checkpoint import checkpoint_manager_cls
from src.kernel import ConfigurationServiceImpl
from src.mesh import mesh_status
from src.realtime import get_broadcaster, get_manager


def test_realtime_facade_points_at_websocket_server() -> None:
    assert get_manager().__name__ == "ConnectionManager"
    assert get_broadcaster().__name__ == "Broadcaster"


def test_checkpoint_facade_points_at_core() -> None:
    assert checkpoint_manager_cls().__name__ == "CheckpointManager"


def test_kernel_exports_configuration_service() -> None:
    assert ConfigurationServiceImpl is not None


def test_mesh_status_is_serializable() -> None:
    snapshot = mesh_status()
    assert "status" in snapshot
