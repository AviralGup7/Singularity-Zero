from unittest.mock import AsyncMock, MagicMock

import pytest

from src.core.events import EventBus, EventType
from src.infrastructure.observability.audit_subscriber import AuditSubscriber
from src.infrastructure.observability.learning_subscriber import LearningSubscriber
from src.infrastructure.observability.notification_subscriber import NotificationSubscriber
from src.infrastructure.security import AuditEvent


@pytest.fixture
def event_bus():
    return EventBus()


@pytest.fixture
def mock_audit_logger():
    return MagicMock()


@pytest.fixture
def mock_notification_manager():
    return AsyncMock()


@pytest.fixture
def mock_learning_integration():
    return AsyncMock()


def test_audit_subscriber(event_bus, mock_audit_logger):
    subscriber = AuditSubscriber(event_bus, mock_audit_logger)
    subscriber.start()

    event_bus.emit(EventType.PIPELINE_STARTED, data={"target": "example.com", "run_id": "run1"})

    mock_audit_logger.log.assert_called_once()
    args, kwargs = mock_audit_logger.log.call_args
    assert kwargs["event"] == AuditEvent.PIPELINE_START
    assert kwargs["resource_id"] == "example.com"
    assert kwargs["details"]["run_id"] == "run1"


@pytest.mark.asyncio
async def test_notification_subscriber(event_bus, mock_notification_manager):
    subscriber = NotificationSubscriber(event_bus, mock_notification_manager)
    subscriber.start()

    # Need to wait for async tasks
    event = event_bus.emit(
        EventType.PIPELINE_STARTED, data={"target": "example.com", "run_id": "run1"}
    )
    await event_bus.flush_pending()

    mock_notification_manager.send_scan_status.assert_called_once_with(
        status="started",
        target="example.com",
        details={"run_id": "run1", "mode": None},
        correlation_id=event.correlation_id,
    )


@pytest.mark.asyncio
async def test_learning_subscriber(event_bus, mock_learning_integration):
    subscriber = LearningSubscriber(event_bus, mock_learning_integration)
    subscriber.start()

    ctx_dict = {"run_id": "run1"}
    event_bus.emit(EventType.PIPELINE_COMPLETE, data={"ctx": ctx_dict})
    await event_bus.flush_pending()

    mock_learning_integration.run_learning_update.assert_called_once_with(ctx_dict)
