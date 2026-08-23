"""Auth audit trail (in-memory)."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import StrEnum

from src.auth.session import Session, SessionKind


class AuthAuditAction(StrEnum):
    LOGIN = "login"
    LOGOUT = "logout"
    DENY = "deny"
    REFRESH = "refresh"
    REVOKE = "revoke"


@dataclass(frozen=True, slots=True)
class AuthAuditEvent:
    action: AuthAuditAction
    subject: str
    role: str
    kind: str
    timestamp: float = field(default_factory=time.time)
    detail: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "action": self.action.value,
            "subject": self.subject,
            "role": self.role,
            "kind": self.kind,
            "timestamp": self.timestamp,
            "detail": self.detail,
        }


class AuthAuditLog:
    def __init__(self, *, limit: int = 2000) -> None:
        self._limit = max(32, int(limit))
        self._items: list[AuthAuditEvent] = []

    def record(
        self, action: AuthAuditAction, session: Session, *, detail: str = ""
    ) -> AuthAuditEvent:
        event = AuthAuditEvent(
            action=action,
            subject=session.subject,
            role=session.role,
            kind=session.kind.value,
            detail=detail,
        )
        self._items.append(event)
        if len(self._items) > self._limit:
            self._items = self._items[-self._limit :]
        return event

    def for_subject(self, subject: str) -> list[AuthAuditEvent]:
        return [event for event in self._items if event.subject == subject]

    def denials(self) -> list[AuthAuditEvent]:
        return [event for event in self._items if event.action is AuthAuditAction.DENY]

    def demo_logins(self) -> int:
        return sum(
            1
            for event in self._items
            if event.action is AuthAuditAction.LOGIN and event.kind == SessionKind.DEMO.value
        )

    def __len__(self) -> int:
        return len(self._items)
