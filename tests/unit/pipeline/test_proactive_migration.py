import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.core.events import EventType, get_event_bus
from src.pipeline.services.pipeline_orchestrator.migration_handler import ProactiveMigrationHandler


@pytest.mark.asyncio
async def test_proactive_migration_handler_evacuates_on_pressure():
    # Setup
    mock_coordinator = MagicMock()
    # Mock migrate_if_needed to return True (migration triggered)
    mock_coordinator.migrate_if_needed = AsyncMock(return_value=True)

    handler = ProactiveMigrationHandler(
        coordinator=mock_coordinator,
        check_interval_seconds=0.1
    )

    mock_actor_ref = MagicMock()
    handler.register_actor("test-actor-1", mock_actor_ref)

    # Track events
    events = []
    def on_evac(event):
        events.append(event)

    sub_id = get_event_bus().subscribe(EventType.GHOST_ACTOR_EVACUATED, on_evac)

    try:
        # Execution
        await handler.start()
        await asyncio.sleep(0.2) # Allow at least one check
        await handler.stop()

        # Verification
        assert mock_coordinator.migrate_if_needed.called
        assert len(events) > 0
        assert events[0].data["actor_id"] == "test-actor-1"
        assert "test-actor-1" not in handler._actor_refs

    finally:
        get_event_bus().unsubscribe(sub_id)

@pytest.mark.asyncio
async def test_proactive_migration_handler_skips_when_no_pressure():
    # Setup
    mock_coordinator = MagicMock()
    # Mock migrate_if_needed to return False (no migration needed)
    mock_coordinator.migrate_if_needed = AsyncMock(return_value=False)

    handler = ProactiveMigrationHandler(
        coordinator=mock_coordinator,
        check_interval_seconds=0.1
    )

    mock_actor_ref = MagicMock()
    handler.register_actor("test-actor-safe", mock_actor_ref)

    try:
        # Execution
        await handler.start()
        await asyncio.sleep(0.2)
        await handler.stop()

        # Verification
        assert mock_coordinator.migrate_if_needed.called
        assert "test-actor-safe" in handler._actor_refs

    finally:
        pass
