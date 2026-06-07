"""Exceptions and types for Burp collaborative OAST integrations."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class OastInteraction:
    interaction_id: str
    interaction_type: str
    client_ip: str
    timestamp: str
    query_string: dict[str, Any] = field(default_factory=dict)
    raw_request: str = ""
    extra: dict[str, Any] = field(default_factory=dict)


class BurpCollaboratorError(Exception):
    pass
