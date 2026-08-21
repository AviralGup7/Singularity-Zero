"""In-memory session registry used by tests and local demo auth."""

from __future__ import annotations

import hashlib
import secrets
import threading
import time
from dataclasses import replace

from src.auth.capabilities import matrix_capabilities
from src.auth.session import Session, SessionKind, demo_session, guest_session, jwt_session


def _token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class SessionRegistry:
    def __init__(self, *, ttl_seconds: float = 12 * 3600) -> None:
        self._ttl = max(60.0, float(ttl_seconds))
        self._lock = threading.RLock()
        self._by_id: dict[str, tuple[Session, float, str | None]] = {}

    def _purge(self, now: float) -> None:
        expired = [key for key, (_, created, _) in self._by_id.items() if now - created > self._ttl]
        for key in expired:
            self._by_id.pop(key, None)

    def register(self, session: Session) -> Session:
        now = time.time()
        digest = _token_digest(session.bearer_token) if session.bearer_token else None
        with self._lock:
            self._purge(now)
            self._by_id[session.subject] = (session, now, digest)
        return session

    def issue_demo(self, name: str = "", role: str = "analyst") -> Session:
        session = demo_session(name, role)
        session = replace(session, capabilities=matrix_capabilities(session.role))
        return self.register(session)

    def issue_guest(self) -> Session:
        return self.register(guest_session(subject=f"guest-{secrets.token_hex(4)}"))

    def issue_jwt(self, subject: str, role: str) -> Session:
        token = secrets.token_urlsafe(24)
        session = jwt_session(subject, role, token)
        session = replace(session, capabilities=matrix_capabilities(role))
        return self.register(session)

    def get(self, subject: str) -> Session | None:
        with self._lock:
            self._purge(time.time())
            packed = self._by_id.get(subject)
            return packed[0] if packed else None

    def resolve_bearer(self, token: str) -> Session | None:
        digest = _token_digest(token)
        with self._lock:
            self._purge(time.time())
            for session, _, stored in self._by_id.values():
                if stored and stored == digest:
                    return session
        return None

    def revoke(self, subject: str) -> bool:
        with self._lock:
            return self._by_id.pop(subject, None) is not None

    def subjects(self) -> list[str]:
        with self._lock:
            return list(self._by_id)

    def __len__(self) -> int:
        with self._lock:
            return len(self._by_id)


def describe(session: Session) -> dict[str, object]:
    return {
        "kind": session.kind.value,
        "subject": session.subject,
        "role": session.role,
        "capabilities": sorted(session.capabilities),
        "has_bearer_token": session.has_bearer_token,
        "demo": session.kind is SessionKind.DEMO,
    }
