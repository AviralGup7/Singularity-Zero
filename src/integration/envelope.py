"""Request and response envelopes exchanged on the console bridge."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from src.integration.correlation import normalize_connection_id, normalize_request_id
from src.integration.errors import ErrorBody, ErrorCode, IntegrationError, status_for
from src.integration.protocol import PROTOCOL_VERSION


@dataclass(slots=True)
class RequestEnvelope:
    command: str
    payload: dict[str, Any] = field(default_factory=dict)
    request_id: str = ""
    idempotency_key: str | None = None
    subject: str | None = None
    bearer_token: str | None = None
    connection_id: str | None = None
    path_params: dict[str, str] = field(default_factory=dict)
    query: dict[str, Any] = field(default_factory=dict)
    issued_at: float = field(default_factory=time.time)
    protocol: str = PROTOCOL_VERSION
    session_kind: str | None = None

    def __post_init__(self) -> None:
        self.request_id = normalize_request_id(self.request_id)
        self.connection_id = normalize_connection_id(self.connection_id)
        if self.bearer_token:
            self.bearer_token = str(self.bearer_token).strip() or None
        if self.subject:
            self.subject = str(self.subject).strip() or None

    def to_dict(self) -> dict[str, Any]:
        return {
            "command": self.command,
            "payload": dict(self.payload),
            "request_id": self.request_id,
            "idempotency_key": self.idempotency_key,
            "subject": self.subject,
            "connection_id": self.connection_id,
            "path_params": dict(self.path_params),
            "query": dict(self.query),
            "issued_at": self.issued_at,
            "protocol": self.protocol,
            "session_kind": self.session_kind,
            "has_bearer_token": bool(self.bearer_token),
        }

    @classmethod
    def from_mapping(cls, data: dict[str, Any]) -> RequestEnvelope:
        raw_payload = data.get("payload")
        payload: dict[str, Any] = dict(raw_payload) if isinstance(raw_payload, dict) else {}
        raw_query = data.get("query")
        query: dict[str, Any] = dict(raw_query) if isinstance(raw_query, dict) else {}
        raw_path_params = data.get("path_params")
        path_params: dict[str, Any] = (
            dict(raw_path_params) if isinstance(raw_path_params, dict) else {}
        )
        return cls(
            command=str(data.get("command") or ""),
            payload=payload,
            request_id=str(data.get("request_id") or ""),
            idempotency_key=(str(data["idempotency_key"]) if data.get("idempotency_key") else None),
            subject=(str(data["subject"]) if data.get("subject") else None),
            bearer_token=(str(data["bearer_token"]) if data.get("bearer_token") else None),
            connection_id=(str(data["connection_id"]) if data.get("connection_id") else None),
            path_params={str(k): str(v) for k, v in path_params.items()},
            query=query,
            issued_at=float(data.get("issued_at") or time.time()),
            protocol=str(data.get("protocol") or PROTOCOL_VERSION),
            session_kind=(str(data["session_kind"]) if data.get("session_kind") else None),
        )


@dataclass(slots=True)
class ResponseEnvelope:
    ok: bool
    command: str
    request_id: str
    status: int
    data: dict[str, Any] = field(default_factory=dict)
    error: ErrorBody | None = None
    events: list[dict[str, Any]] = field(default_factory=list)
    skipped: bool = False
    protocol: str = PROTOCOL_VERSION

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "ok": self.ok,
            "command": self.command,
            "request_id": self.request_id,
            "status": self.status,
            "data": dict(self.data),
            "events": list(self.events),
            "skipped": self.skipped,
            "protocol": self.protocol,
        }
        if self.error is not None:
            payload["error"] = self.error.to_dict()
        return payload

    @classmethod
    def success(
        cls,
        command: str,
        request_id: str,
        data: dict[str, Any] | None = None,
        *,
        status: int = 200,
        events: list[dict[str, Any]] | None = None,
    ) -> ResponseEnvelope:
        return cls(
            ok=True,
            command=command,
            request_id=request_id,
            status=status,
            data=dict(data or {}),
            events=list(events or []),
        )

    @classmethod
    def from_error(cls, command: str, request_id: str, exc: IntegrationError) -> ResponseEnvelope:
        skipped = exc.code is ErrorCode.SKIPPED
        return cls(
            ok=skipped,
            command=command,
            request_id=request_id,
            status=exc.status if not skipped else 200,
            error=exc.body,
            skipped=skipped,
            data={"skipped": True} if skipped else {},
        )

    @classmethod
    def from_code(
        cls,
        command: str,
        request_id: str,
        code: ErrorCode,
        message: str,
        **details: Any,
    ) -> ResponseEnvelope:
        body = ErrorBody(code=code, message=message, details=details or None)
        return cls(
            ok=False,
            command=command,
            request_id=request_id,
            status=status_for(code),
            error=body,
        )
