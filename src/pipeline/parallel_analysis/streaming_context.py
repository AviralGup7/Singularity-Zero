"""Streaming context wrapper for large target sets."""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any


class StreamingAnalysisContext:
    """Wraps a context object, exposing async generators for large collections."""

    def __init__(self, context: Any) -> None:
        self._context = context

    def iter_live_hosts(self) -> AsyncIterator[str]:
        try:
            hosts = self._context.live_hosts
        except AttributeError:
            hosts = self._context.result.live_hosts
        yield from hosts

    def iter_urls(self) -> AsyncIterator[str]:
        try:
            urls = self._context.urls
        except AttributeError:
            urls = self._context.result.urls
        yield from urls

    def iter_subdomains(self) -> AsyncIterator[str]:
        try:
            subs = self._context.subdomains
        except AttributeError:
            subs = self._context.result.subdomains
        yield from subs
