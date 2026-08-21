"""Dispatch UI commands onto ConsoleRuntime.

This is the integration root: envelopes in, domain work, envelopes out.
FastAPI (or any HTTP adapter) should call ``ConsoleGateway.dispatch`` and
not reimplement authz or demo-notification policy.
"""

from __future__ import annotations

import time
from typing import Any

from src.auth.rbac import PermissionError as RbacPermissionError
from src.auth.session import Session
from src.console.audit import BridgeAudit
from src.console.connection import ConnectionRegistry
from src.console.context import RequestContext
from src.console.handlers import HANDLERS
from src.console.rate_limit import TokenBucket
from src.console.runtime import ConsoleRuntime
from src.integration.authz import resolve_allowed
from src.integration.batch import parse_batch
from src.integration.commands import CommandName, CommandSpec, get_command
from src.integration.envelope import RequestEnvelope, ResponseEnvelope
from src.integration.errors import (
    ErrorCode,
    IntegrationError,
    bad_request,
    forbidden,
    unauthorized,
)
from src.integration.idempotency import IdempotencyCache
from src.integration.protocol import protocol_compatible
from src.integration.serialize import jsonable


_MUTATING = frozenset(
    {
        CommandName.JOBS_START.value,
        CommandName.JOBS_STOP.value,
        CommandName.INTEL_SEED.value,
        CommandName.SESSION_DEMO.value,
        CommandName.SESSION_REVOKE.value,
        CommandName.NOTIFICATIONS_MARK_READ.value,
        CommandName.NOTIFICATIONS_MARK_ALL.value,
        CommandName.NOTIFICATIONS_DELETE.value,
        CommandName.HANDSHAKE_OPEN.value,
    }
)


class ConsoleGateway:
    def __init__(self, runtime: ConsoleRuntime | None = None) -> None:
        self.runtime = runtime or ConsoleRuntime()
        self.connections = ConnectionRegistry()
        self.idempotency = IdempotencyCache()
        self.limiter = TokenBucket()
        self.audit = BridgeAudit()
        self._bind_store_events()

    def _bind_store_events(self) -> None:
        from src.integration.events import StreamFrame

        def _on_job(event: Any) -> None:
            self.connections.publish(StreamFrame.job(event.to_dict()))

        def _on_note(notification: Any) -> None:
            self.connections.publish(StreamFrame.notification(notification.to_dict()))

        self.runtime.store.subscribe(_on_job)
        self.runtime.inbox.subscribe(_on_note)

    def resolve_session(self, envelope: RequestEnvelope) -> Session | None:
        if envelope.bearer_token:
            found = self.runtime.sessions.resolve_bearer(envelope.bearer_token)
            if found is not None:
                return found
        if envelope.subject:
            found = self.runtime.sessions.get(envelope.subject)
            if found is not None:
                return found
        return None

    def dispatch(self, envelope: RequestEnvelope, *, now: float | None = None) -> ResponseEnvelope:
        epoch = float(now if now is not None else time.time())
        command = str(envelope.command or "").strip()
        if not command:
            return ResponseEnvelope.from_error("", envelope.request_id, bad_request("command required"))
        if command == CommandName.BATCH_EXECUTE.value:
            return self._dispatch_batch(envelope, now=epoch)
        try:
            spec = get_command(command)
        except IntegrationError as exc:
            return ResponseEnvelope.from_error(command, envelope.request_id, exc)
        cached = self.idempotency.get(envelope.idempotency_key) if envelope.idempotency_key else None
        if cached is not None:
            return ResponseEnvelope.success(command, envelope.request_id, cached, status=200)
        try:
            data = self._execute(spec, envelope, epoch)
        except IntegrationError as exc:
            session = self.resolve_session(envelope)
            self.audit.record(command, session, ok=False)
            return ResponseEnvelope.from_error(command, envelope.request_id, exc)
        except RbacPermissionError as exc:
            err = forbidden(str(exc), capability=exc.capability, role=exc.role)
            return ResponseEnvelope.from_error(command, envelope.request_id, err)
        except KeyError as exc:
            from src.integration.errors import not_found

            return ResponseEnvelope.from_error(command, envelope.request_id, not_found(str(exc)))
        except Exception as exc:  # noqa: BLE001
            return ResponseEnvelope.from_code(
                command,
                envelope.request_id,
                ErrorCode.INTERNAL,
                str(exc) or "internal error",
            )
        if envelope.idempotency_key:
            self.idempotency.put(envelope.idempotency_key, data)
        self.audit.record(command, self.resolve_session(envelope), ok=True)
        return ResponseEnvelope.success(command, envelope.request_id, jsonable(data))

    def _execute(self, spec: CommandSpec, envelope: RequestEnvelope, now: float) -> dict[str, Any]:
        if envelope.protocol and not protocol_compatible(envelope.protocol):
            raise IntegrationError(
                ErrorCode.PROTOCOL,
                f"incompatible protocol {envelope.protocol}",
                details={"server": "1.0"},
            )
        session = self.resolve_session(envelope)
        resolve_allowed(session, spec)
        if spec.key in _MUTATING:
            subject = session.subject if session is not None else envelope.subject or "anonymous"
            self.limiter.take(subject, now=now)
        handler = HANDLERS.get(spec.key)
        if handler is None:
            raise bad_request("handler missing", command=spec.key)
        ctx = RequestContext(
            runtime=self.runtime,
            envelope=envelope,
            spec=spec,
            session=session,
            connection_id=envelope.connection_id,
            now=now,
            extras={"connections": self.connections},
        )
        return handler(ctx)

    def _dispatch_batch(self, envelope: RequestEnvelope, *, now: float) -> ResponseEnvelope:
        session = self.resolve_session(envelope)
        if session is None:
            return ResponseEnvelope.from_error(
                CommandName.BATCH_EXECUTE.value,
                envelope.request_id,
                unauthorized(),
            )
        try:
            items = parse_batch(envelope.payload)
        except IntegrationError as exc:
            return ResponseEnvelope.from_error(CommandName.BATCH_EXECUTE.value, envelope.request_id, exc)
        results: list[dict[str, Any]] = []
        for item in items:
            child = RequestEnvelope(
                command=str(item["command"]),
                payload=dict(item["payload"]),
                path_params=dict(item["path_params"]),
                subject=envelope.subject,
                bearer_token=envelope.bearer_token,
                connection_id=envelope.connection_id,
                protocol=envelope.protocol,
                request_id=envelope.request_id,
            )
            response = self.dispatch(child, now=now)
            results.append(response.to_dict())
        return ResponseEnvelope.success(
            CommandName.BATCH_EXECUTE.value,
            envelope.request_id,
            {"results": results, "count": len(results)},
        )
