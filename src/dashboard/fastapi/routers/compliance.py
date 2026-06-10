"""Compliance access-log and evidence-custody endpoints.

Provides server-side persistence for the Access Logs and Evidence Custody
pages which previously relied on client-side ``sessionStorage`` only.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import time
import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from src.dashboard.fastapi.dependencies import require_admin, require_auth

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/compliance", tags=["Compliance"])


# ---------------------------------------------------------------------------
# SQLite helpers (shared connection via app state or fallback)
# ---------------------------------------------------------------------------

_SQLITE_SCHEMA = """
CREATE TABLE IF NOT EXISTS compliance_access_logs (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    "user" TEXT NOT NULL,
    action TEXT NOT NULL,
    resource TEXT NOT NULL,
    reason TEXT NOT NULL,
    details TEXT DEFAULT '{}',
    outcome TEXT DEFAULT 'success',
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS evidence_custody (
    id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL,
    data TEXT NOT NULL,
    hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS evidence_custody_chain (
    id TEXT PRIMARY KEY,
    evidence_id TEXT NOT NULL,
    action TEXT NOT NULL,
    "user" TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    hash_before TEXT,
    hash_after TEXT,
    details TEXT NOT NULL,
    created_at REAL NOT NULL
);
"""


def _ensure_db(conn: sqlite3.Connection) -> None:
    """Run schema migrations if tables don't exist."""
    try:
        conn.executescript(_SQLITE_SCHEMA)
    except Exception as exc:
        logger.debug("Schema ensure failed (tables may already exist): %s", exc)


def _get_conn(request: Request) -> sqlite3.Connection:
    """Return a SQLite connection for compliance data."""
    services = getattr(request.app.state, "services", None)
    store = getattr(services, "store", None) if services else None
    if store is not None and hasattr(store, "_get_conn"):
        conn = store._get_conn()
        _ensure_db(conn)
        return conn
    # Fallback: use a standalone SQLite database file
    from src.learning.repositories.telemetry_store import TelemetryStore

    fallback = TelemetryStore()
    fallback.initialize()
    conn = fallback._get_conn()
    _ensure_db(conn)
    return conn


def _row_to_dict(cursor: sqlite3.Cursor, row: tuple) -> dict[str, Any]:
    return {col[0]: row[idx] for idx, col in enumerate(cursor.description)}


# ---------------------------------------------------------------------------
# Access Logs (replaces client-side complianceLogger.ts)
# ---------------------------------------------------------------------------


@router.get(
    "/access-logs",
    summary="List compliance access log entries",
)
async def list_access_logs(
    request: Request,
    limit: int = Query(200, ge=1, le=2000),
    user: str | None = None,
    action: str | None = None,
    _auth: Any = Depends(require_auth),
) -> list[dict[str, Any]]:
    conn = _get_conn(request)
    query = 'SELECT id, timestamp, "user", action, resource, reason, details, outcome, created_at FROM compliance_access_logs'
    clauses: list[str] = []
    params: list[Any] = []
    if user:
        clauses.append('"user" = ?')
        params.append(user)
    if action:
        clauses.append("action = ?")
        params.append(action)
    if clauses:
        query += " WHERE " + " AND ".join(clauses)
    query += " ORDER BY created_at DESC LIMIT ?"
    params.append(limit)
    cursor = conn.execute(query, params)
    rows = [_row_to_dict(cursor, row) for row in cursor.fetchall()]
    # Parse JSON details
    for row in rows:
        if isinstance(row.get("details"), str):
            try:
                row["details"] = json.loads(row["details"])
            except (json.JSONDecodeError, TypeError):
                row["details"] = {}
    return rows


@router.post(
    "/access-logs",
    summary="Record a compliance access log entry",
    dependencies=[Depends(require_admin)],
)
async def create_access_log(
    request: Request,
    payload: dict[str, Any],
) -> dict[str, Any]:
    log_id = str(payload.get("id") or f"alog-{uuid.uuid4().hex[:12]}")
    now = time.time()
    conn = _get_conn(request)
    conn.execute(
        'INSERT INTO compliance_access_logs (id, timestamp, "user", action, resource, reason, details, outcome, created_at) '
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        [
            log_id,
            payload.get("timestamp") or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
            str(payload.get("user") or "anonymous"),
            str(payload.get("action") or ""),
            str(payload.get("resource") or ""),
            str(payload.get("reason") or ""),
            json.dumps(payload.get("details") or {}),
            str(payload.get("outcome") or "success"),
            now,
        ],
    )
    conn.commit()
    return {"id": log_id, "status": "created"}


# ---------------------------------------------------------------------------
# Evidence Custody (replaces client-side evidenceChain.ts)
# ---------------------------------------------------------------------------


@router.get(
    "/evidence",
    summary="List evidence custody records",
)
async def list_evidence(
    request: Request,
    limit: int = Query(200, ge=1, le=2000),
    finding_id: str | None = None,
    _auth: Any = Depends(require_auth),
) -> list[dict[str, Any]]:
    conn = _get_conn(request)
    query = "SELECT id, finding_id, data, hash, created_at, created_by FROM evidence_custody"
    clauses: list[str] = []
    params: list[Any] = []
    if finding_id:
        clauses.append("finding_id = ?")
        params.append(finding_id)
    if clauses:
        query += " WHERE " + " AND ".join(clauses)
    query += " ORDER BY created_at DESC LIMIT ?"
    params.append(limit)
    cursor = conn.execute(query, params)
    records = [_row_to_dict(cursor, row) for row in cursor.fetchall()]

    # Attach custody chain to each record
    for rec in records:
        chain_cursor = conn.execute(
            'SELECT id, evidence_id, action, "user", timestamp, hash_before, hash_after, details '
            "FROM evidence_custody_chain WHERE evidence_id = ? ORDER BY created_at ASC",
            [rec["id"]],
        )
        rec["custody_chain"] = [_row_to_dict(chain_cursor, row) for row in chain_cursor.fetchall()]

    return records


@router.post(
    "/evidence",
    summary="Create an evidence custody record",
)
async def create_evidence(
    request: Request,
    payload: dict[str, Any],
    _auth: Any = Depends(require_auth),
) -> dict[str, Any]:
    finding_id = str(payload.get("finding_id") or "").strip()
    data = str(payload.get("data") or "")
    if not finding_id or not data:
        raise HTTPException(status_code=422, detail="finding_id and data are required")

    import hashlib

    evidence_id = str(payload.get("id") or f"evidence-{uuid.uuid4().hex[:12]}")
    data_hash = hashlib.sha256(data.encode("utf-8")).hexdigest()
    created_by = str(payload.get("created_by") or "anonymous")
    created_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    now = time.time()

    conn = _get_conn(request)
    conn.execute(
        "INSERT OR REPLACE INTO evidence_custody (id, finding_id, data, hash, created_at, created_by) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        [evidence_id, finding_id, data, data_hash, created_at, created_by],
    )
    # Also add the initial custody-chain entry
    chain_id = f"custody-{uuid.uuid4().hex[:12]}"
    conn.execute(
        'INSERT INTO evidence_custody_chain (id, evidence_id, action, "user", timestamp, hash_after, details, created_at) '
        "VALUES (?, ?, 'created', ?, ?, ?, 'Evidence created and hashed', ?)",
        [chain_id, evidence_id, created_by, created_at, data_hash, now],
    )
    conn.commit()
    return {"id": evidence_id, "hash": data_hash, "status": "created"}


@router.post(
    "/evidence/{evidence_id}/access",
    summary="Log an access event on an evidence record",
)
async def log_evidence_access(
    evidence_id: str,
    request: Request,
    payload: dict[str, Any],
    _auth: Any = Depends(require_auth),
) -> dict[str, Any]:
    conn = _get_conn(request)
    cursor = conn.execute("SELECT id FROM evidence_custody WHERE id = ?", [evidence_id])
    if not cursor.fetchone():
        raise HTTPException(status_code=404, detail="Evidence record not found")

    user = str(payload.get("user") or "anonymous")
    details = str(payload.get("details") or "Evidence accessed for review")
    now = time.time()
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))
    chain_id = f"custody-{uuid.uuid4().hex[:12]}"
    conn.execute(
        'INSERT INTO evidence_custody_chain (id, evidence_id, action, "user", timestamp, details, created_at) '
        "VALUES (?, ?, 'accessed', ?, ?, ?, ?)",
        [chain_id, evidence_id, user, ts, details, now],
    )
    conn.commit()
    return {"chain_id": chain_id, "status": "recorded"}


@router.post(
    "/evidence/{evidence_id}/verify",
    summary="Verify the cryptographic integrity of an evidence record",
)
async def verify_evidence(
    evidence_id: str,
    request: Request,
    _auth: Any = Depends(require_auth),
) -> dict[str, Any]:
    import hashlib

    conn = _get_conn(request)
    cursor = conn.execute("SELECT id, data, hash FROM evidence_custody WHERE id = ?", [evidence_id])
    row = cursor.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Evidence record not found")

    current_hash = hashlib.sha256(row[1].encode("utf-8")).hexdigest()
    is_valid = current_hash == row[2]
    return {
        "valid": is_valid,
        "message": "Evidence integrity verified"
        if is_valid
        else "Evidence integrity compromised - hash mismatch!",
        "expected_hash": row[2],
        "actual_hash": current_hash,
    }
