"""Stateful UI-side interaction against the console gateway.

Mirrors ``ConsoleClient`` + ``ConsoleConnection`` in the frontend so tests
can exercise the same sequence operators use after Demo Sign In: handshake,
list jobs, start a scan, read the inbox without touching JWT notification
routes.
"""

from __future__ import annotations

from typing import Any

from src.console.gateway import ConsoleGateway
from src.console.http import ConsoleHttpAdapter, HttpResponse
from src.integration.commands import CommandName
from src.integration.envelope import RequestEnvelope, ResponseEnvelope
from src.integration.protocol import PROTOCOL_VERSION


class ConsoleInteraction:
    def __init__(self, gateway: ConsoleGateway | None = None) -> None:
        self.gateway = gateway or ConsoleGateway()
        self.http = ConsoleHttpAdapter(self.gateway)
        self.subject: str | None = None
        self.connection_id: str | None = None
        self.role: str | None = None
        self.capabilities: list[str] = []
        self.last: ResponseEnvelope | None = None

    def _headers(self) -> dict[str, str]:
        headers = {"X-Console-Protocol": PROTOCOL_VERSION}
        if self.subject:
            headers["X-Console-Subject"] = self.subject
        if self.connection_id:
            headers["X-Console-Connection"] = self.connection_id
        return headers

    def call(self, command: str, payload: dict[str, Any] | None = None, **path_params: str) -> ResponseEnvelope:
        envelope = RequestEnvelope(
            command=command,
            payload=dict(payload or {}),
            subject=self.subject,
            connection_id=self.connection_id,
            path_params=path_params,
            protocol=PROTOCOL_VERSION,
        )
        self.last = self.gateway.dispatch(envelope)
        data = self.last.data
        if command in {CommandName.HANDSHAKE_OPEN.value, CommandName.SESSION_DEMO.value} and self.last.ok:
            session = data.get("session") if isinstance(data.get("session"), dict) else {}
            self.subject = str(session.get("subject") or self.subject or "")
            self.role = str(session.get("role") or self.role or "")
            caps = session.get("capabilities") or []
            self.capabilities = [str(item) for item in caps]
            if data.get("connection_id"):
                self.connection_id = str(data["connection_id"])
        return self.last

    def http_call(self, method: str, path: str, *, body: dict[str, Any] | None = None, query: dict[str, Any] | None = None) -> HttpResponse:
        return self.http.handle(method, path, headers=self._headers(), body=body, query=query)

    def demo_sign_in(self, name: str = "Demo Analyst", role: str = "analyst") -> ResponseEnvelope:
        return self.call(CommandName.SESSION_DEMO.value, {"name": name, "role": role})

    def handshake(self, name: str = "Demo Analyst", role: str = "analyst") -> ResponseEnvelope:
        return self.call(
            CommandName.HANDSHAKE_OPEN.value,
            {"client": "security-console", "protocol": PROTOCOL_VERSION, "kind": "demo", "name": name, "role": role},
        )

    def start_scan(self, url: str, *, findings: int = 0, fail_at: str | None = None) -> ResponseEnvelope:
        payload: dict[str, Any] = {"base_url": url, "findings": findings}
        if fail_at:
            payload["fail_at"] = fail_at
        return self.call(CommandName.JOBS_START.value, payload)

    def list_jobs(self, **query: Any) -> ResponseEnvelope:
        envelope = RequestEnvelope(
            command=CommandName.JOBS_LIST.value,
            subject=self.subject,
            connection_id=self.connection_id,
            query=dict(query),
        )
        self.last = self.gateway.dispatch(envelope)
        return self.last

    def list_notifications(self) -> ResponseEnvelope:
        return self.call(CommandName.NOTIFICATIONS_LIST.value)

    def snapshot(self) -> ResponseEnvelope:
        return self.call(CommandName.SNAPSHOT_GET.value)

    def lookup(self, value: str) -> ResponseEnvelope:
        envelope = RequestEnvelope(
            command=CommandName.INTEL_LOOKUP.value,
            subject=self.subject,
            connection_id=self.connection_id,
            query={"q": value},
        )
        self.last = self.gateway.dispatch(envelope)
        return self.last

    def seed_intel(self, value: str, *, verdict: str = "malicious", source: str = "manual") -> ResponseEnvelope:
        return self.call(
            CommandName.INTEL_SEED.value,
            {"value": value, "verdict": verdict, "source": source, "score": 0.9},
        )

    def poll(self) -> ResponseEnvelope:
        return self.call(CommandName.STREAM_POLL.value)
