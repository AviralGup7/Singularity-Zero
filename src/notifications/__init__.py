"""Notification domain."""

from src.notifications.digest import Digest, build_digest
from src.notifications.events import (
    Notification,
    NotificationEvent,
    NotificationPriority,
    from_finding,
    from_job_status,
)
from src.notifications.inbox import Inbox
from src.notifications.policy import should_fetch, should_open_stream
from src.notifications.routing import Route, route_for

__all__ = [
    "Digest",
    "Inbox",
    "Notification",
    "NotificationEvent",
    "NotificationPriority",
    "Route",
    "build_digest",
    "from_finding",
    "from_job_status",
    "route_for",
    "should_fetch",
    "should_open_stream",
]
