"""Opt-in API security services for the FastAPI dashboard."""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import secrets
import sqlite3
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import jwt
from fastapi import HTTPException, Request, status

from src.infrastructure.db.sqlite_utils import (
    SQLITE_BUSY_TIMEOUT_MS as _BUSY_TIMEOUT_MS,
)
from src.infrastructure.db.sqlite_utils import (
    SQLITE_CONNECT_TIMEOUT_SECONDS as _CONNECT_TIMEOUT_SECONDS,
)
from src.infrastructure.db.sqlite_utils import (
    SQLITE_LOCK_RETRY_ATTEMPTS as _LOCK_RETRY_ATTEMPTS,
)
from src.infrastructure.db.sqlite_utils import (
    SQLITE_LOCK_RETRY_BASE_DELAY_SECONDS as _LOCK_RETRY_BASE_DELAY_SECONDS,
)
from src.infrastructure.db.sqlite_utils import (
    is_locked_error as _is_locked_error,
)
from src.infrastructure.db.sqlite_utils import (
    safe_close,
)

try:
    from argon2 import PasswordHasher
    from argon2.exceptions import (
        InvalidHashError,
        VerificationError,
        VerifyMismatchError,
    )

    _ARGON2_AVAILABLE = True
except Exception:  # pragma: no cover - argon2-cffi is a project dep but be defensive
    PasswordHasher = None  # type: ignore[assignment]
    InvalidHashError = Exception  # type: ignore[assignment,misc]
    VerificationError = Exception  # type: ignore[assignment,misc]
    VerifyMismatchError = Exception  # type: ignore[assignment,misc]
    _ARGON2_AVAILABLE = False

ROLE_ORDER = {"read_only": 1, "worker": 2, "admin": 3}
VALID_ROLES = frozenset(ROLE_ORDER)

# Minimum acceptable entropy (Shannon) of a configured secret in production.
# 4.0 bits/char roughly corresponds to a strong, random alphanumeric key
# (~96 bits of entropy in a 24-char random string).
_MIN_SECRET_ENTROPY_BITS_PER_CHAR = 3.5

# Single shared PasswordHasher so verification uses the same parameters as
# hashing. The defaults (time_cost=3, memory_cost=64MiB, parallelism=4) are
# appropriate for interactive auth; tune via env if needed in the future.
_argon2_hasher: PasswordHasher | None = None
if _ARGON2_AVAILABLE and PasswordHasher is not None:
    _argon2_hasher = PasswordHasher()


def api_security_enabled() -> bool:
    return os.getenv("ENABLE_API_SECURITY", "true").strip().lower() == "true"


_fallback_secret: str | None = None


def _shannon_entropy_bits_per_char(value: str) -> float:
    """Return the Shannon entropy of ``value`` in bits-per-character.

    A higher value means the key is harder to guess. The result is in
    ``[0, log2(alphabet_size)]`` bits per character; an all-same-character
    string returns 0.0.
    """
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    length = len(value)
    entropy = 0.0
    for c in counts.values():
        p = c / length
        entropy -= p * math.log2(p)
    return entropy


# Lock guarding the lazy ``_fallback_secret`` so concurrent first-callers
# can't race on the check-then-set.  Reads after initialization are
# lock-free because ``str`` is immutable.
_fallback_secret_lock = threading.Lock()


def app_secret_key() -> str:
    """Return the active dashboard secret key.

    Resolution order:

    1. ``APP_SECRET_KEY`` or ``DASHBOARD_API_KEY`` environment variable.
    2. In non-production environments, a per-process random fallback
       generated on first call.  In production this raises.
    """
    key = os.getenv("APP_SECRET_KEY") or os.getenv("DASHBOARD_API_KEY")
    is_prod = os.getenv("APP_ENV") == "production"

    if not key:
        if is_prod:
            raise ValueError(
                "CRITICAL SECURITY RISK: APP_SECRET_KEY is not set. "
                "A high-entropy secret key must be configured in production via environment variables."
            )
        # Lazy, thread-safe initialization of the dev fallback.
        global _fallback_secret
        if _fallback_secret is None:
            with _fallback_secret_lock:
                if _fallback_secret is None:
                    _fallback_secret = secrets.token_hex(32)
        return _fallback_secret  # type: ignore[return-value]

    if is_prod and key in ("change-me-in-production", "dev-dashboard-secret"):
        raise ValueError(
            f"CRITICAL SECURITY RISK: The APP_SECRET_KEY is set to a default value ('{key}'). "
            "A high-entropy secret key must be configured in production environments."
        )
    if is_prod and _shannon_entropy_bits_per_char(key) < _MIN_SECRET_ENTROPY_BITS_PER_CHAR:
        raise ValueError(
            "CRITICAL SECURITY RISK: APP_SECRET_KEY entropy is too low "
            f"({_shannon_entropy_bits_per_char(key):.2f} bits/char, "
            f"min {_MIN_SECRET_ENTROPY_BITS_PER_CHAR:.2f}). "
            "Use a long, random secret (e.g. `python -c 'import secrets; print(secrets.token_urlsafe(48))'`)."
        )
    if is_prod and len(key) < 32:
        raise ValueError(
            "CRITICAL SECURITY RISK: APP_SECRET_KEY is shorter than 32 characters. "
            "Use a long, random secret."
        )
    return key


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


def hash_api_key(api_key: str) -> str:
    """Return a stable, slow hash of ``api_key`` for storage in SQLite.

    Uses Argon2id (preferred) when the ``argon2-cffi`` package is available.
    Argon2 hashes embed their parameters and salt, so the stored value is
    self-describing. As a final fallback (e.g. environments without
    argon2-cffi) we use a SHA-256 digest with a server-side pepper to
    avoid storing the bare key digest.
    """
    if _ARGON2_AVAILABLE and _argon2_hasher is not None:
        return _argon2_hasher.hash(api_key)
    pepper = os.getenv("API_KEY_PEPPER", "")
    digest = hashlib.sha256()
    digest.update(pepper.encode("utf-8"))
    digest.update(b":")
    digest.update(api_key.encode("utf-8"))
    return f"sha256${digest.hexdigest()}"


def verify_api_key(api_key: str, stored_hash: str) -> bool:
    """Verify ``api_key`` against the stored ``stored_hash`` produced by :func:`hash_api_key`."""
    if not stored_hash:
        return False
    if _ARGON2_AVAILABLE and _argon2_hasher is not None and not stored_hash.startswith("sha256$"):
        try:
            _argon2_hasher.verify(stored_hash, api_key)
            return True
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            return False
    if stored_hash.startswith("sha256$"):
        return hmac.compare_digest(stored_hash, hash_api_key(api_key))
    return False


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
    tenant_id: str | None = "default"
    api_key_id: str | None = None
    auth_method: str = "api_key"


class SecurityStore:
    """Small SQLite store for API keys, security events, and CSP reports."""

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
        self._lock = threading.RLock()
        self._initialized = False

    @staticmethod
    def _is_locked_error(exc: BaseException) -> bool:
        message = str(exc).lower()
        return "database is locked" in message or "database table is locked" in message

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=_CONNECT_TIMEOUT_SECONDS)
        try:
            conn.execute(f"PRAGMA busy_timeout={_BUSY_TIMEOUT_MS}")
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
        except Exception:
            safe_close(conn)
            raise
        return conn

    def _is_locked_error(self, exc: BaseException) -> bool:
        return _is_locked_error(exc)

    def _with_conn(self, operation: Callable[[sqlite3.Connection], Any]) -> Any:
        last_exc: sqlite3.OperationalError | None = None
        for attempt in range(_LOCK_RETRY_ATTEMPTS):
            with self._lock:
                try:
                    with self._connect() as conn:
                        return operation(conn)
                except sqlite3.OperationalError as exc:
                    last_exc = exc
                    if not self._is_locked_error(exc) or attempt == _LOCK_RETRY_ATTEMPTS - 1:
                        raise
            time.sleep(_LOCK_RETRY_BASE_DELAY_SECONDS * (2**attempt))
        if last_exc is not None:
            raise last_exc
        return None

    def init(self) -> None:
        with self._lock:
            if self._initialized:
                return
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            with self._connect() as conn:
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

        def _op(conn: sqlite3.Connection) -> Any:
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
            return row

        row = self._with_conn(_op)
        return self._row_to_key(row)

    def generate_key(self, role: str) -> dict[str, Any]:
        raw_key = f"cp_{secrets.token_urlsafe(32)}"
        record = self.add_key(raw_key, role)
        record["api_key"] = raw_key
        record["masked_key"] = mask_api_key(raw_key)
        return record

    def authenticate_key(self, api_key: str) -> Principal | None:
        """Authenticate ``api_key`` by hashing and matching.

        NOTE: With Argon2 the hash is salted so we cannot look up by hash
        directly. Instead we fetch *all* active (non-revoked) keys, then
        verify the presented key against each stored hash. This is
        expensive at scale but acceptable for a dashboard service that has
        at most a few dozen keys; if that changes, store a SHA-256 *index*
        alongside the Argon2 hash and look up the candidate first.
        """
        now = utc_now()

        def _op(conn: sqlite3.Connection) -> Any:
            rows = conn.execute(
                """
                SELECT id, role, revoked_at, key_hash FROM api_keys
                WHERE revoked_at IS NULL
                """,
            ).fetchall()
            for row in rows:
                if verify_api_key(api_key, row[3]):
                    conn.execute("UPDATE api_keys SET last_used_at = ? WHERE id = ?", (now, row[0]))
                    return (row[0], row[1])
            return None

        row = self._with_conn(_op)
        if row is None:
            return None
        return Principal(user=row[0], role=row[1], api_key_id=row[0], auth_method="api_key")

    def list_keys(self) -> list[dict[str, Any]]:
        rows = self._with_conn(
            lambda conn: conn.execute(
                """
                SELECT id, prefix, role, created_at, last_used_at, revoked_at
                FROM api_keys
                ORDER BY created_at DESC
                """
            ).fetchall()
        )
        return [self._row_to_key(row) for row in rows]

    def revoke_key(self, key_id: str) -> bool:
        def _op(conn: sqlite3.Connection) -> int:
            cur = conn.execute(
                "UPDATE api_keys SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL",
                (utc_now(), key_id),
            )
            return int(cur.rowcount)

        return int(self._with_conn(_op)) > 0

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
        detail_text = (
            json.dumps(detail, separators=(",", ":"), default=str)
            if isinstance(detail, dict)
            else detail
        )

        def _op(conn: sqlite3.Connection) -> None:
            conn.execute(
                """
                INSERT INTO security_events
                    (timestamp, event_type, status_code, method, path, client_ip, api_key_id, detail)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    utc_now(),
                    event_type,
                    status_code,
                    method,
                    path,
                    client_ip,
                    api_key_id,
                    detail_text,
                ),
            )

        self._with_conn(_op)

    def list_events(self, limit: int = 100) -> list[dict[str, Any]]:
        rows = self._with_conn(
            lambda conn: conn.execute(
                """
                SELECT id, timestamp, event_type, status_code, method, path, client_ip, api_key_id, detail
                FROM security_events
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        )
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

        def _op(conn: sqlite3.Connection) -> None:
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

        self._with_conn(_op)
        self.record_event(
            "csp_violation",
            status_code=204,
            method=request.method,
            path=request.url.path,
            client_ip=client_ip,
            detail=report,
        )

    def list_csp_reports(self, limit: int = 50) -> list[dict[str, Any]]:
        rows = self._with_conn(
            lambda conn: conn.execute(
                """
                SELECT id, timestamp, client_ip, user_agent, report_json
                FROM csp_reports
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        )
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
        "tenant_id": principal.tenant_id or "default",
        "api_key_id": principal.api_key_id,
        "exp": expires_at,
        "iat": datetime.now(UTC),
    }
    token = jwt.encode(payload, app_secret_key(), algorithm="HS256")
    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in": 900,
        "role": principal.role,
    }


def authenticate_jwt_token(token: str) -> Principal | None:
    try:
        payload = jwt.decode(
            token,
            app_secret_key(),
            algorithms=["HS256"],
            options={"require": ["exp", "iat"], "verify_exp": True},
        )
    except jwt.PyJWTError:
        return None
    role = str(payload.get("role") or (payload.get("roles") or ["read_only"])[0])
    if role not in VALID_ROLES:
        return None
    return Principal(
        user=str(payload.get("sub", "dashboard")),
        role=role,
        tenant_id=str(payload.get("tenant_id", "default")),
        api_key_id=payload.get("api_key_id"),
        auth_method="jwt",
    )


def has_role(role: str, allowed_roles: set[str]) -> bool:
    # Bug #39 fix: the previous implementation used
    # ``ROLE_ORDER.get(allowed, 999)`` as the *required* rank for any role
    # in ``allowed_roles`` that wasn't in ``ROLE_ORDER``. That meant an
    # unknown role string like ``"superadmin"`` or a typo such as
    # ``"Admin"`` would silently require rank 999, which every known role
    # trivially satisfies - turning a misconfigured allow-list into a
    # privilege escalation. We now (a) only honor allow-list entries that
    # are in ``ROLE_ORDER`` and (b) treat unknown role strings as zero
    # privilege so they can never satisfy any allow-list on their own.
    caller_rank = ROLE_ORDER.get(role, 0)
    for allowed in allowed_roles:
        if allowed not in ROLE_ORDER:
            # Skip unknown allowed roles instead of treating them as the
            # most permissive entry in the table.
            continue
        if caller_rank >= ROLE_ORDER[allowed]:
            return True
    return False


def raise_for_roles(principal: Principal, allowed_roles: set[str]) -> None:
    if not has_role(principal.role, allowed_roles):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient API key scope",
        )


def compare_key(candidate: str, expected: str) -> bool:
    return hmac.compare_digest(candidate or "", expected or "")
