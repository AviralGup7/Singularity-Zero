"""Notification domain policy. Channel sinks stay in infrastructure."""

from src.notifications.policy import should_fetch, should_open_stream

__all__ = ["should_fetch", "should_open_stream"]
