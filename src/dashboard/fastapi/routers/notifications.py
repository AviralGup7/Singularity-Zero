"""REST API router for notification management.

Endpoints:
  GET    /api/notifications          - List notifications (paginated)
  GET    /api/notifications/unread-count - Get unread count
  PATCH  /api/notifications/{id}/read   - Mark single notification as read
  PATCH  /api/notifications/read-all    - Mark all as read
  DELETE /api/notifications/{id}        - Delete single notification
  DELETE /api/notifications             - Delete all notifications
  GET    /api/notifications/stream      - SSE stream for real-time notifications
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Query, Request
from pydantic import BaseModel

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/notifications", tags=["Notifications"])


class NotificationResponse(BaseModel):
    id: str
    event: str
    priority: str
    title: str
    message: str
    metadata: str
    source: str
    correlation_id: str | None = None
    entity_id: str | None = None
    entity_type: str | None = None
    href: str | None = None
    read: bool
    created_at: str


class NotificationListResponse(BaseModel):
    notifications: list[dict[str, Any]]
    total: int
    unread_count: int
    limit: int
    offset: int


class UnreadCountResponse(BaseModel):
    unread_count: int


class MarkReadResponse(BaseModel):
    success: bool
    unread_count: int


class DeleteResponse(BaseModel):
    success: bool
    deleted: int


def _get_storage(request: Request) -> Any:
    """Retrieve the NotificationStorage from app state."""
    storage = getattr(request.app.state, "notification_storage", None)
    if storage is None:
        from fastapi import HTTPException
        raise HTTPException(status_code=503, detail="Notification storage not initialized")
    return storage


@router.get("", response_model=NotificationListResponse)
async def list_notifications(
    request: Request,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    unread_only: bool = Query(default=False),
) -> dict[str, Any]:
    """Return paginated notifications, newest first."""
    storage = _get_storage(request)
    notifications = storage.list_notifications(limit=limit, offset=offset, unread_only=unread_only)
    unread_count = storage.count_unread()
    return {
        "notifications": notifications,
        "total": len(notifications),
        "unread_count": unread_count,
        "limit": limit,
        "offset": offset,
    }


@router.get("/unread-count", response_model=UnreadCountResponse)
async def unread_count(request: Request) -> dict[str, int]:
    """Return the count of unread notifications."""
    storage = _get_storage(request)
    return {"unread_count": storage.count_unread()}


@router.patch("/{notification_id}/read", response_model=MarkReadResponse)
async def mark_notification_read(
    notification_id: str,
    request: Request,
) -> dict[str, Any]:
    """Mark a single notification as read."""
    storage = _get_storage(request)
    success = storage.mark_read(notification_id)
    unread_count = storage.count_unread()
    return {"success": success, "unread_count": unread_count}


@router.patch("/read-all", response_model=MarkReadResponse)
async def mark_all_read(request: Request) -> dict[str, Any]:
    """Mark all notifications as read."""
    storage = _get_storage(request)
    updated = storage.mark_all_read()
    unread_count = storage.count_unread()
    return {"success": True, "unread_count": unread_count}


@router.delete("/{notification_id}", response_model=DeleteResponse)
async def delete_notification(
    notification_id: str,
    request: Request,
) -> dict[str, Any]:
    """Delete a single notification."""
    storage = _get_storage(request)
    success = storage.delete(notification_id)
    return {"success": success, "deleted": 1 if success else 0}


@router.delete("", response_model=DeleteResponse)
async def delete_all_notifications(request: Request) -> dict[str, Any]:
    """Delete all notifications."""
    storage = _get_storage(request)
    deleted = storage.delete_all()
    return {"success": True, "deleted": deleted}


@router.get("/stream")
async def notification_stream(request: Request) -> Any:
    """SSE endpoint for real-time notification streaming."""
    from src.infrastructure.notifications.broadcaster import get_notification_broadcaster

    broadcaster = get_notification_broadcaster()
    return await broadcaster.connect(request)
