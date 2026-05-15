"""Opt-in API security services for the FastAPI dashboard."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import threading
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import jwt
from fastapi import HTTPException, Request, status

ROLE_ORDER = {"read_only": 1, "worker": 2, "admin": 3}
VALID_ROLES = frozenset(ROLE_ORDER)


def api_security_enabled() -> bool:
    return os.getenv("ENABLE_API_SECURITY", "false").strip().lower() == "true"


def app_secret_key() -> str:
    return os.getenv("APP_SECRET_KEY") or os.getenv("DASHBOARD_API_KEY") or "dev-dashboard-secret"


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


def hash_api_key(api_key: str) -> str:
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


def mask_api_key(api_key: str | None = None, prefix: str | None = None) -> str:
    if api_key:
        if len(api_key) <= 10:
            return f"{api_key[:2]}...{api_key[-2:]}"
        return f"{api_key[:6]}...{api_key[-4:]}"
    if prefix:
        return f"{prefix}..."
    return "masked"


@dataclass(frozen=True)
class Principal:
    user: str
    role: str
    api_key_id: str | None = None
    auth_method: str = "api_key"


class SecurityStore:
    """Small SQLite store for API keys, security events, and CSP reports."""

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
        self._lock = threading.RLock()
        self._initialized = False

    def init(self) -> None:
        with self._lock:
            if self._initialized:
                return
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("PRAGMA journal_mode=WAL")
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS api_keys (
                        id TEXT PRIMARY KEY,
                        key_hash TEXT UNIQUE NOT NULL,
                        prefix TEXT NOT NULL,
                        role TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        last_used_at TEXT,
                        revoked_at TEXT
                    )
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS security_events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT NOT NULL,
                        event_type TEXT NOT NULL,
                        status_code INTEGER,
                        method TEXT,
                        path TEXT,
                        client_ip TEXT,
                        api_key_id TEXT,
                        detail TEXT
                    )
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS csp_reports (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT NOT NULL,
                        client_ip TEXT,
                        user_agent TEXT,
                        report_json TEXT NOT NULL
                    )
                    """
                )
            self._initialized = True
            self.seed_from_config()

    def seed_from_config(self) -> None:
        for key, role in _load_configured_keys():
            self.add_key(key, role, key_id=f"seed_{hash_api_key(key)[:12]}", if_missing=True)

    def add_key(
        self,
        api_key: str,
        role: str,
        *,
        key_id: str | None = None,
        if_missing: bool = False,
    ) -> dict[str, Any]:
        if role not in VALID_ROLES:
            raise ValueError(f"Invalid API key role: {role}")
        now = utc_now()
        key_hash = hash_api_key(api_key)
        prefix = api_key[:8]
        key_id = key_id or f"key_{secrets.token_hex(8)}"
        with self._lock, sqlite3.connect(self.db_path) as conn:
            try:
                conn.execute(
                    """
                    INSERT INTO api_keys (id, key_hash, prefix, role, created_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (key_id, key_hash, prefix, role, now),
                )
            except sqlite3.IntegrityError:
                if not if_missing:
                    raise
            row = conn.execute(
                "SELECT id, prefix, role, created_at, last_used_at, revoked_at FROM api_keys WHERE key_hash = ?",
                (key_hash,),
            ).fetchone()
        return self._row_to_key(row)

    def generate_key(self, role: str) -> dict[str, Any]:
        raw_key = f"cp_{secrets.token_urlsafe(32)}"
        record = self.add_key(raw_key, role)
        record["api_key"] = raw_key
        record["masked_key"] = mask_api_key(raw_key)
        return record

    def authenticate_key(self, api_key: str) -> Principal | None:
        key_hash = hash_api_key(api_key)
        now = utc_now()
        with self._lock, sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                """
                SELECT id, role, revoked_at FROM api_keys
                WHERE key_hash = ?
                """,
                (key_hash,),
            ).fetchone()
            if row is None or row[2] is not None:
                return None
            conn.execute("UPDATE api_keys SET last_used_at = ? WHERE id = ?", (now, row[0]))
        return Principal(user=row[0], role=row[1], api_key_id=row[0], auth_method="api_key")

    def list_keys(self) -> list[dict[str, Any]]:
        with self._lock, sqlite3.connect(self.db_path) as conn:
            rows = conn.execute(
                """
                SELECT id, prefix, role, created_at, last_used_at, revoked_at
                FROM api_keys
                ORDER BY created_at DESC
                """
            ).fetchall()
        return [self._row_to_key(row) for row in rows]

    def revoke_key(self, key_id: str) -> bool:
        with self._lock, sqlite3.connect(self.db_path) as conn:
            cur = conn.execute(
                "UPDATE api_keys SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL",
                (utc_now(), key_id),
            )
            return cur.rowcount > 0

    def record_event(
        self,
        event_type: str,
        *,
        status_code: int | None = None,
        method: str | None = None,
        path: str | None = None,
        client_ip: str | None = None,
        api_key_id: str | None = None,
        detail: str | dict[str, Any] | None = None,
    ) -> None:
        detail_text = json.dumps(detail, separators=(",", ":"), default=str) if isinstance(detail, dict) else detail
        with self._lock, sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO security_events
                    (timestamp, event_type, status_code, method, path, client_ip, api_key_id, detail)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (utc_now(), event_type, status_code, method, path, client_ip, api_key_id, detail_text),
            )

    def list_events(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock, sqlite3.connect(self.db_path) as conn:
            rows = conn.execute(
                """
                SELECT id, timestamp, event_type, status_code, method, path, client_ip, api_key_id, detail
                FROM security_events
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [
            {
                "id": row[0],
                "timestamp": row[1],
                "event_type": row[2],
                "status_code": row[3],
                "method": row[4],
                "path": row[5],
                "client_ip": row[6],
                "api_key_id": row[7],
                "detail": row[8] or "",
            }
            for row in rows
        ]

    def record_csp_report(self, request: Request, report: dict[str, Any]) -> None:
        client_ip = request.client.host if request.client else "unknown"
        with self._lock, sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO csp_reports (timestamp, client_ip, user_agent, report_json)
                VALUES (?, ?, ?, ?)
                """,
                (
                    utc_now(),
                    client_ip,
                    request.headers.get("user-agent", ""),
                    json.dumps(report, separators=(",", ":"), default=str),
                ),
            )
        self.record_event(
            "csp_violation",
            status_code=204,
            method=request.method,
            path=request.url.path,
            client_ip=client_ip,
            detail=report,
        )

    def list_csp_reports(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._lock, sqlite3.connect(self.db_path) as conn:
            rows = conn.execute(
                """
                SELECT id, timestamp, client_ip, user_agent, report_json
                FROM csp_reports
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [
            {
                "id": row[0],
                "timestamp": row[1],
                "client_ip": row[2],
                "user_agent": row[3],
                "report": json.loads(row[4]),
            }
            for row in rows
        ]

    @staticmethod
    def _row_to_key(row: Any) -> dict[str, Any]:
        return {
            "id": row[0],
            "masked_key": mask_api_key(prefix=row[1]),
            "role": row[2],
            "created_at": row[3],
            "last_used_at": row[4],
            "revoked_at": row[5],
            "active": row[5] is None,
        }


def _load_configured_keys() -> list[tuple[str, str]]:
    configured: list[tuple[str, str]] = []
    raw_json = os.getenv("API_KEYS_JSON") or os.getenv("DASHBOARD_API_KEYS_JSON")
    if raw_json:
        configured.extend(_parse_key_config(json.loads(raw_json)))

    config_path = os.getenv("API_KEYS_CONFIG_PATH")
    if config_path:
        path = Path(config_path)
    else:
        path = Path("configs") / "api_keys.json"
    if path.exists():
        configured.extend(_parse_key_config(json.loads(path.read_text(encoding="utf-8"))))

    dashboard_key = os.getenv("DASHBOARD_API_KEY")
    if dashboard_key:
        configured.append((dashboard_key, "admin"))

    admin_keys = [k.strip() for k in os.getenv("DASHBOARD_ADMIN_KEYS", "").split(",") if k.strip()]
    configured.extend((key, "admin") for key in admin_keys)
    return configured


def _parse_key_config(payload: Any) -> list[tuple[str, str]]:
    if isinstance(payload, dict) and isinstance(payload.get("keys"), list):
        return [
            (str(item["key"]), str(item.get("role", "read_only")))
            for item in payload["keys"]
            if isinstance(item, dict) and item.get("key")
        ]
    if isinstance(payload, dict):
        return [(str(key), str(role)) for key, role in payload.items()]
    return []


def create_jwt(principal: Principal) -> dict[str, Any]:
    expires_at = datetime.now(UTC) + timedelta(minutes=15)
    payload = {
        "sub": principal.user,
        "roles": [principal.role],
        "role": principal.role,
        "api_key_id": principal.api_key_id,
        "exp": expires_at,
        "iat": datetime.now(UTC),
    }
    token = jwt.encode(payload, app_secret_key(), algorithm="HS256")
    return {"access_token": token, "token_type": "bearer", "expires_in": 900, "role": principal.role}


def authenticate_jwt_token(token: str) -> Principal | None:
    try:
        payload = jwt.decode(token, app_secret_key(), algorithms=["HS256"])
    except jwt.PyJWTError:
        return None
    role = str(payload.get("role") or (payload.get("roles") or ["read_only"])[0])
    if role not in VALID_ROLES:
        return None
    return Principal(
        user=str(payload.get("sub", "dashboard")),
        role=role,
        api_key_id=payload.get("api_key_id"),
        auth_method="jwt",
    )


def has_role(role: str, allowed_roles: set[str]) -> bool:
    return any(ROLE_ORDER.get(role, 0) >= ROLE_ORDER.get(allowed, 999) for allowed in allowed_roles)


def raise_for_roles(principal: Principal, allowed_roles: set[str]) -> None:
    if not has_role(principal.role, allowed_roles):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient API key scope",
        )


def compare_key(candidate: str, expected: str) -> bool:
    return hmac.compare_digest(candidate or "", expected or "")
