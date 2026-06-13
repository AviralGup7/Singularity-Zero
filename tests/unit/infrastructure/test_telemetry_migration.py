from unittest.mock import AsyncMock, MagicMock

import pytest

from src.core.frontier.ghost_actor import GhostMeshCoordinator
from src.infrastructure.frontier.ghost_actor_registry import GhostMeshRegistry
from src.infrastructure.mesh.gossip import MeshNode


@pytest.mark.asyncio
async def test_coordinator_triggers_migration_on_telemetry_pressure():
    # Setup
    mock_registry = MagicMock(spec=GhostMeshRegistry)
    mock_registry.find_actor = AsyncMock(return_value="node-1")
    mock_registry.register_actor = AsyncMock()

    local_node = MeshNode(id="node-1", host="127.0.0.1", port=8000)
    # Simulate pressure
    local_node.cpu_usage = 95.0

    mock_gossip = MagicMock()
    mock_gossip.local_node = local_node

    # Target node with low usage
    target_node = MeshNode(
        id="node-2", host="127.0.0.2", port=8000, cpu_usage=10.0, ram_available_mb=2048
    )
    mock_gossip.mesh_nodes.return_value = [local_node, target_node]

    coordinator = GhostMeshCoordinator(mock_registry, mock_gossip)

    # Mock actor
    mock_actor_ref = MagicMock()
    # If ask is called, return normal health
    mock_actor_ref.ask.return_value = {"actor_id": "test-1", "evacuation_recommended": False}
    mock_actor_ref.proxy.return_value.actor_id.get.return_value = "actor:test-1"

    # Execution
    triggered = await coordinator.migrate_if_needed(mock_actor_ref, {"actor_id": "test-1"})

    # Verification
    assert triggered is True
    # Verify registry update to new node
    mock_registry.register_actor.assert_called_with("actor:test-1", "node-2")


@pytest.mark.asyncio
async def test_coordinator_skips_migration_when_healthy():
    # Setup
    mock_registry = MagicMock(spec=GhostMeshRegistry)
    local_node = MeshNode(id="node-1", host="127.0.0.1", port=8000)
    # Healthy state
    local_node.cpu_usage = 10.0
    local_node.ram_available_mb = 1000.0

    mock_gossip = MagicMock()
    mock_gossip.local_node = local_node

    coordinator = GhostMeshCoordinator(mock_registry, mock_gossip)

    mock_actor_ref = MagicMock()
    mock_actor_ref.ask.return_value = {"evacuation_recommended": False}

    # Execution
    triggered = await coordinator.migrate_if_needed(mock_actor_ref, {"actor_id": "test-1"})

    # Verification
    assert triggered is False
