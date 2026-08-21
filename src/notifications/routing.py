"""Route notifications to channels without importing Slack/email clients."""

from __future__ import annotations

from dataclasses import dataclass

from src.notifications.events import Notification, NotificationPriority


@dataclass(frozen=True, slots=True)
class Route:
    inbox: bool
    sse: bool
    webhook: bool
    email: bool


def route_for(notification: Notification) -> Route:
    if notification.priority is NotificationPriority.CRITICAL:
        return Route(inbox=True, sse=True, webhook=True, email=True)
    if notification.priority is NotificationPriority.HIGH:
        return Route(inbox=True, sse=True, webhook=True, email=False)
    if notification.priority is NotificationPriority.LOW:
        return Route(inbox=True, sse=False, webhook=False, email=False)
    return Route(inbox=True, sse=True, webhook=False, email=False)
