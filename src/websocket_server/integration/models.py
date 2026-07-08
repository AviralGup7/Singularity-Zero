"""Pydantic models and type aliases for WebSocket integration."""

from __future__ import annotations

from collections.abc import Callable

from pydantic import BaseModel, ConfigDict, Field


class BroadcastPayload(BaseModel):
    """Request body for admin WebSocket broadcast."""

    model_config = ConfigDict(extra="forbid")

    channel: str = Field(..., min_length=1, max_length=256)
    message: str = Field(..., min_length=1, max_length=4096)


class AdminConfigPayload(BaseModel):
    """Request body for admin WebSocket config updates."""

    model_config = ConfigDict(extra="forbid")

    max_connections_per_user: int | None = Field(default=None, ge=1, le=1000)
    max_connections_per_ip: int | None = Field(default=None, ge=1, le=1000)
    stale_timeout: float | None = Field(default=None, ge=1.0, le=3600.0)
    max_connection_attempts_per_minute: int | None = Field(default=None, ge=1, le=600)


JobTenantResolver = Callable[[str], str | None]
