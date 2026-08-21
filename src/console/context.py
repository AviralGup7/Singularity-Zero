"""Per-request context assembled by the gateway."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from src.auth.session import Session
from src.console.runtime import ConsoleRuntime
from src.integration.commands import CommandSpec
from src.integration.envelope import RequestEnvelope


@dataclass(slots=True)
class RequestContext:
    runtime: ConsoleRuntime
    envelope: RequestEnvelope
    spec: CommandSpec
    session: Session | None = None
    connection_id: str | None = None
    now: float = 0.0
    extras: dict[str, Any] = field(default_factory=dict)

    @property
    def payload(self) -> dict[str, Any]:
        return self.envelope.payload

    @property
    def query(self) -> dict[str, Any]:
        return self.envelope.query

    def param(self, name: str, default: str = "") -> str:
        if name in self.envelope.path_params:
            return str(self.envelope.path_params[name])
        if name in self.envelope.payload:
            return str(self.envelope.payload[name])
        if name in self.envelope.query:
            return str(self.envelope.query[name])
        return default
