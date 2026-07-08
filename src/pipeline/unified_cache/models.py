"""Models, enums, and constants for the unified cache."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class Backend(StrEnum):
    SQLITE = "sqlite"
    FILE = "file"


class CachePriority(StrEnum):
    NORMAL = "normal"
    TRANSIENT = "transient"
    CRITICAL = "critical"


class TTLMode(StrEnum):
    HARD_TTL = "hard_ttl"
    STALE_WHILE_REVALIDATE = "stale_while_revalidate"


@dataclass
class NamespaceRouting:
    default_backend: Backend
    default_priority: CachePriority
    split_threshold_bytes: int | None = None


_NAMESPACE_ROUTING: dict[str, NamespaceRouting] = {
    "resume": NamespaceRouting(
        default_backend=Backend.SQLITE, default_priority=CachePriority.CRITICAL
    ),
    "probe": NamespaceRouting(
        default_backend=Backend.SQLITE, default_priority=CachePriority.NORMAL
    ),
    "subdomain": NamespaceRouting(
        default_backend=Backend.SQLITE, default_priority=CachePriority.NORMAL
    ),
    "tool_output": NamespaceRouting(
        default_backend=Backend.FILE, default_priority=CachePriority.TRANSIENT
    ),
    "screenshot": NamespaceRouting(
        default_backend=Backend.FILE, default_priority=CachePriority.TRANSIENT
    ),
    "http_response": NamespaceRouting(
        default_backend=Backend.SQLITE, default_priority=CachePriority.NORMAL
    ),
}

NAMESPACE_ROUTING = _NAMESPACE_ROUTING

PRIORITY_RANK: dict[str, int] = {
    CachePriority.TRANSIENT.value: 0,
    CachePriority.NORMAL.value: 1,
    CachePriority.CRITICAL.value: 2,
}

ROUTING_PREFIX = "__route__:"
DATA_PREFIX = "__data__:"

_DEFAULT_ROUTING = NamespaceRouting(
    default_backend=Backend.SQLITE, default_priority=CachePriority.NORMAL
)
_ROUTING_PREFIX = ROUTING_PREFIX
_DATA_PREFIX = DATA_PREFIX
