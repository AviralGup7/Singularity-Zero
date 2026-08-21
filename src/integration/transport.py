"""In-process transport used by tests and local loopback."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from src.integration.envelope import RequestEnvelope, ResponseEnvelope
from src.integration.errors import ErrorCode, IntegrationError


Dispatcher = Callable[[RequestEnvelope], ResponseEnvelope]


@dataclass
class HttpResult:
    status: int
    headers: dict[str, str]
    body: dict[str, Any]


class InMemoryTransport:
    def __init__(self, dispatcher: Dispatcher) -> None:
        self._dispatch = dispatcher
        self.calls: list[RequestEnvelope] = []

    def send(self, envelope: RequestEnvelope) -> ResponseEnvelope:
        self.calls.append(envelope)
        try:
            return self._dispatch(envelope)
        except IntegrationError as exc:
            return ResponseEnvelope.from_error(envelope.command, envelope.request_id, exc)
        except Exception as exc:  # noqa: BLE001 - transport must never raise to the UI
            return ResponseEnvelope.from_code(
                envelope.command,
                envelope.request_id,
                ErrorCode.INTERNAL,
                str(exc) or "internal error",
            )
