"""Record bridge commands onto the auth audit log when a session exists."""

from __future__ import annotations

from src.auth.audit import AuthAuditAction, AuthAuditLog
from src.auth.session import Session
from src.integration.commands import CommandName


_LOGIN = {CommandName.SESSION_DEMO.value, CommandName.HANDSHAKE_OPEN.value}
_LOGOUT = {CommandName.SESSION_REVOKE.value, CommandName.HANDSHAKE_CLOSE.value}


class BridgeAudit:
    def __init__(self) -> None:
        self.log = AuthAuditLog()

    def record(self, command: str, session: Session | None, *, ok: bool) -> None:
        if session is None:
            return
        if not ok:
            action = AuthAuditAction.DENY
        elif command in _LOGIN:
            action = AuthAuditAction.LOGIN
        elif command in _LOGOUT:
            action = AuthAuditAction.LOGOUT
        else:
            action = AuthAuditAction.REFRESH
        self.log.record(action, session, detail=f"{command}:{'ok' if ok else 'err'}")
