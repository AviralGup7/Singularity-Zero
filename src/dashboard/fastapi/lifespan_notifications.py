"""Phase 2: Notification system startup — storage, broadcaster, manager."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import FastAPI

logger = logging.getLogger(__name__)


def startup_notifications(app: FastAPI, config: Any) -> None:
    """Notification system — storage, broadcaster, manager."""
    from src.infrastructure.notifications.broadcaster import get_notification_broadcaster
    from src.infrastructure.notifications.in_app import InAppNotifier
    from src.infrastructure.notifications.manager import ManagerConfig, NotificationManager
    from src.infrastructure.notifications.storage import NotificationStorage

    notif_db_path = config.output_root / "notifications.db"
    app.state.notification_storage = NotificationStorage(str(notif_db_path))
    app.state.notification_broadcaster = get_notification_broadcaster()
    logger.info("Notification storage initialized at %s", notif_db_path)

    in_app_notifier = InAppNotifier()
    in_app_notifier.bind_storage(app.state.notification_storage)
    in_app_notifier.bind_broadcaster(app.state.notification_broadcaster)

    notif_manager = NotificationManager(ManagerConfig())
    notif_manager.register_notifier("in_app", in_app_notifier)
    app.state.notification_manager = notif_manager
    logger.info("NotificationManager initialized with in_app channel")
