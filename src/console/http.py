"""HTTP adapter that does not import FastAPI.

Maps method/path/headers/body onto ``ConsoleGateway.dispatch``. A later
FastAPI router can wrap ``handle_http`` in a few lines.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qs

from src.console.gateway import ConsoleGateway
from src.integration.correlation import normalize_request_id
from src.integration.envelope import RequestEnvelope, ResponseEnvelope
from src.integration.errors import IntegrationError, not_found
from src.integration.protocol import (
    CONNECTION_HEADER,
    IDEMPOTENCY_HEADER,
    MEDIA_TYPE,
    PROTOCOL_HEADER,
    PROTOCOL_VERSION,
    REQUEST_ID_HEADER,
    SESSION_KIND_HEADER,
    SUBJECT_HEADER,
)
from src.integration.routes import match_route


def _header(headers: dict[str, str], name: str) -> str:
    lowered = {str(key).lower(): str(value) for key, value in headers.items()}
    return lowered.get(name.lower(), "")


def _bearer(headers: dict[str, str]) -> str | None:
    raw = _header(headers, "authorization")
    if raw.lower().startswith("bearer "):
        token = raw[7:].strip()
        return token or None
    return None


def _query(raw: str | dict[str, Any] | None) -> dict[str, Any]:
    if raw is None:
        return {}
    if isinstance(raw, dict):
        return dict(raw)
    parsed = parse_qs(raw, keep_blank_values=False)
    return {key: values[-1] if values else "" for key, values in parsed.items()}


def envelope_from_http(
    method: str,
    path: str,
    *,
    headers: dict[str, str] | None = None,
    body: dict[str, Any] | str | bytes | None = None,
    query: str | dict[str, Any] | None = None,
) -> RequestEnvelope:
    headers = headers or {}
    try:
        matched = match_route(method, path)
    except IntegrationError:
        raise
    payload: dict[str, Any]
    if isinstance(body, dict):
        payload = dict(body)
    elif isinstance(body, (bytes, bytearray)):
        text = body.decode("utf-8") or "{}"
        payload = json.loads(text) if text.strip() else {}
    elif isinstance(body, str) and body.strip():
        payload = json.loads(body)
    else:
        payload = {}
    if not isinstance(payload, dict):
        payload = {}
    return RequestEnvelope(
        command=matched.spec.key,
        payload=payload,
        request_id=_header(headers, REQUEST_ID_HEADER),
        idempotency_key=_header(headers, IDEMPOTENCY_HEADER) or None,
        subject=_header(headers, SUBJECT_HEADER) or None,
        bearer_token=_bearer(headers),
        connection_id=_header(headers, CONNECTION_HEADER) or None,
        path_params=matched.params,
        query=_query(query),
        protocol=_header(headers, PROTOCOL_HEADER) or PROTOCOL_VERSION,
        session_kind=_header(headers, SESSION_KIND_HEADER) or None,
    )


@dataclass(slots=True)
class HttpResponse:
    status: int
    headers: dict[str, str]
    body: dict[str, Any]


def response_to_http(envelope: ResponseEnvelope) -> HttpResponse:
    headers = {
        "Content-Type": MEDIA_TYPE,
        REQUEST_ID_HEADER: envelope.request_id,
        PROTOCOL_HEADER: envelope.protocol,
    }
    return HttpResponse(status=envelope.status, headers=headers, body=envelope.to_dict())


class ConsoleHttpAdapter:
    def __init__(self, gateway: ConsoleGateway | None = None) -> None:
        self.gateway = gateway or ConsoleGateway()

    def handle(
        self,
        method: str,
        path: str,
        *,
        headers: dict[str, str] | None = None,
        body: dict[str, Any] | str | bytes | None = None,
        query: str | dict[str, Any] | None = None,
        now: float | None = None,
    ) -> HttpResponse:
        try:
            envelope = envelope_from_http(method, path, headers=headers, body=body, query=query)
        except IntegrationError as exc:
            request_id = normalize_request_id((headers or {}).get(REQUEST_ID_HEADER, ""))
            failed = ResponseEnvelope.from_error("", request_id, exc)
            return response_to_http(failed)
        result = self.gateway.dispatch(envelope, now=now)
        return response_to_http(result)


def handle_http(
    gateway: ConsoleGateway,
    method: str,
    path: str,
    **kwargs: Any,
) -> HttpResponse:
    return ConsoleHttpAdapter(gateway).handle(method, path, **kwargs)


def missing_route(method: str, path: str) -> HttpResponse:
    request_id = normalize_request_id("")
    failed = ResponseEnvelope.from_error(
        "", request_id, not_found("no console route", method=method, path=path)
    )
    return response_to_http(failed)
