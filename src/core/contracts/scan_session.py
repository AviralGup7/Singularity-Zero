"""Scan session and authentication credential contracts."""

from __future__ import annotations

import abc
import json
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from cryptography.fernet import Fernet

from src.infrastructure.security.encryption import decrypt_string, encrypt_string

@dataclass(frozen=True, slots=True)
class SessionCredential:
    type: str
    name: str
    value: str
    scope: frozenset[str] = field(default_factory=frozenset)
    expires_at: datetime | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

@dataclass
class ScanSession:
    scan_id: str
    credentials: dict[str, SessionCredential] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    auth_headers: dict[str, str] = field(default_factory=dict)
    base_url: str = ""
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    last_used: datetime = field(default_factory=lambda: datetime.now(UTC))
    _encryption_key: str = field(default_factory=lambda: os.environ.get("SEC_ENCRYPTION_KEY", "") or Fernet.generate_key().decode("utf-8"))

    def __post_init__(self) -> None:
        if not self._encryption_key:
            object.__setattr__(self, "_encryption_key", Fernet.generate_key().decode("utf-8"))

    def add_credential(self, cred: SessionCredential) -> None:
        self.credentials[cred.name] = cred
        self.last_used = datetime.now(UTC)

    def _url_matches_scope(self, url: str, scopes: frozenset[str]) -> bool:
        if not scopes:
            return True
        parsed_url = url.lower()
        return any(pattern.lower() in parsed_url for pattern in scopes)

    def get_credential_for_url(self, url: str) -> SessionCredential | None:
        for cred in self.credentials.values():
            if cred.expires_at is not None and cred.expires_at < datetime.now(UTC):
                continue
            if self._url_matches_scope(url, cred.scope):
                return cred
        return None

    def encrypt_value(self, value: str) -> str:
        if not value:
            return ""
        return encrypt_string(value, self._encryption_key)

    def decrypt_value(self, value: str) -> str:
        if not value:
            return ""
        try:
            return decrypt_string(value, self._encryption_key)
        except Exception:
            return value

    def to_headers(self, url: str) -> dict[str, str]:
        headers: dict[str, str] = {}
        cred = self.get_credential_for_url(url)
        if cred is None:
            return headers
        value = self.decrypt_value(cred.value)
        if cred.type == "bearer_token":
            headers["Authorization"] = f"Bearer {value}"
        elif cred.type == "basic_auth":
            import base64
            headers["Authorization"] = f"Basic {base64.b64encode(value.encode('utf-8')).decode('utf-8')}"
        elif cred.type == "api_key":
            safe_name = cred.name.upper().replace(" ", "_")
            headers[safe_name] = value
        elif cred.type == "oauth2":
            headers["Authorization"] = f"Bearer {value}"
        for key, value in self.auth_headers.items():
            if key not in headers:
                headers[key] = value
        return headers

    def to_cookies(self, url: str) -> dict[str, str]:
        cookies: dict[str, str] = {}
        scoped = [c for c in self.credentials.values() if c.scope]
        if not scoped or any(self._url_matches_scope(url, c.scope) for c in scoped):
            for name, value in self.cookies.items():
                cookies[name] = value
        return cookies

    def to_state_dict(self) -> dict[str, Any]:
        return {
            "scan_session_id": self.scan_id,
            "credentials": {
                name: {
                    "type": cred.type,
                    "name": cred.name,
                    "value": cred.value,
                    "scope": list(cred.scope),
                    "expires_at": cred.expires_at.isoformat() if cred.expires_at else None,
                    "metadata": cred.metadata,
                }
                for name, cred in self.credentials.items()
            },
            "cookies": self.cookies,
            "auth_headers": self.auth_headers,
            "base_url": self.base_url,
            "created_at": self.created_at.isoformat(),
            "last_used": self.last_used.isoformat(),
        }

    @classmethod
    def restore(cls, state: dict[str, Any], scan_id: str) -> ScanSession | None:
        if not state:
            return None
        session = cls(scan_id=scan_id)
        for name, payload in state.get("credentials", {}).items():
            session.credentials[name] = SessionCredential(
                type=str(payload.get("type", "session_cookie")),
                name=str(payload.get("name", name)),
                value=str(payload.get("value", "")),
                scope=frozenset(payload.get("scope", []) or []),
                expires_at=datetime.fromisoformat(payload["expires_at"]) if payload.get("expires_at") else None,
                metadata=dict(payload.get("metadata", {}) or {}),
            )
        session.cookies = dict(state.get("cookies", {}) or {})
        session.auth_headers = dict(state.get("auth_headers", {}) or {})
        session.base_url = str(state.get("base_url", "") or "")
        created_at = state.get("created_at")
        if created_at:
            session.created_at = datetime.fromisoformat(created_at)
        last_used = state.get("last_used")
        if last_used:
            session.last_used = datetime.fromisoformat(last_used)
        return session

class SessionStore(ABC):
    @abstractmethod
    def save_session(self, session: ScanSession) -> str:
        ...

    @abstractmethod
    def load_session(self, scan_id: str) -> ScanSession | None:
        ...

    @abstractmethod
    def delete_session(self, scan_id: str) -> None:
        ...

class LocalSessionStore(SessionStore):
    def __init__(self, checkpoint_dir: str | Path) -> None:
        self._sessions_dir = Path(checkpoint_dir) / "sessions"
        self._sessions_dir.mkdir(parents=True, exist_ok=True)

    def _session_path(self, scan_id: str) -> Path:
        return self._sessions_dir / f"{scan_id}.json"

    def save_session(self, session: ScanSession) -> str:
        path = self._session_path(session.scan_id)
        path.write_text(json.dumps(session.to_state_dict(), indent=2))
        return str(path)

    def load_session(self, scan_id: str) -> ScanSession | None:
        path = self._session_path(scan_id)
        if not path.exists():
            return None
        state = json.loads(path.read_text())
        return ScanSession.restore(state, scan_id)

    def delete_session(self, scan_id: str) -> None:
        path = self._session_path(scan_id)
        if path.exists():
            path.unlink()

@dataclass(frozen=True, slots=True)
class SessionProvisioningOutput:
    session_id: str
    username: str | None
    auth_method: str
    success: bool
    error: str | None
    credentials_provisioned: tuple[str, ...]
