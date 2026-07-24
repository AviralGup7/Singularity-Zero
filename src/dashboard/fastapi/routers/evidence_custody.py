"""Evidence custody chain endpoints for the FastAPI dashboard.

Provides server-side persistence for evidence custody records that were
previously stored only in browser sessionStorage.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import threading
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from src.dashboard.fastapi.dependencies import require_auth
from src.dashboard.fastapi.schemas import ErrorResponse

router = APIRouter(prefix="/api/evidence-custody", tags=["Evidence Custody"])

# ---------------------------------------------------------------------------
# Persistent evidence store (Defect 5 fix: backed by JSON file)
# ---------------------------------------------------------------------------

_evidence_lock = threading.Lock()
_evidence_records: list[dict[str, Any]] = []
_evidence_store_path: Path | None = None
_evidence_store_loaded = False


def _resolve_store_path() -> Path:
    """Return the path to the evidence custody JSON store."""
    global _evidence_store_path
    if _evidence_store_path is not None:
        return _evidence_store_path
    pipeline_dir = Path(".pipeline")
    pipeline_dir.mkdir(parents=True, exist_ok=True)
    _evidence_store_path = pipeline_dir / "evidence_custody.json"
    return _evidence_store_path


def _load_evidence_from_disk() -> None:
    """Load evidence records from disk into memory (once)."""
    global _evidence_store_loaded
    if _evidence_store_loaded:
        return
    _evidence_store_loaded = True
    store_path = _resolve_store_path()
    if not store_path.exists():
        return
    try:
        data = json.loads(store_path.read_text(encoding="utf-8"))
        if isinstance(data, list):
            _evidence_records.extend(data)
    except (json.JSONDecodeError, OSError) as exc:
        import logging

        logging.getLogger(__name__).warning("Failed to load evidence store: %s", exc)


def _persist_evidence_to_disk() -> None:
    """Atomically write evidence records to disk."""
    store_path = _resolve_store_path()
    tmp_fd, tmp_path = tempfile.mkstemp(
        dir=store_path.parent, suffix=".tmp", prefix="evidence_"
    )
    try:
        with os.fdopen(tmp_fd, "w", encoding="utf-8") as tmp_f:
            json.dump(_evidence_records, tmp_f, indent=2)
            tmp_f.flush()
            os.fsync(tmp_f.fileno())
        Path(tmp_path).replace(store_path)
    except Exception:
        try:
            Path(tmp_path).unlink(missing_ok=True)
        except OSError:
            pass


def _sha256(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


class CustodyEntryModel(BaseModel):
    """Single custody-chain entry."""

    id: str = Field(default_factory=lambda: f"custody-{uuid.uuid4()}")
    evidence_id: str
    action: str  # created | accessed | modified | exported | deleted
    user: str = "anonymous"
    timestamp: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    hash_before: str | None = None
    hash_after: str | None = None
    details: str = ""


class EvidenceRecordModel(BaseModel):
    """Full evidence record with custody chain."""

    id: str = Field(default_factory=lambda: f"evidence-{uuid.uuid4()}")
    finding_id: str
    data: str
    hash: str
    created_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    created_by: str = "anonymous"
    custody_chain: list[dict[str, Any]] = Field(default_factory=list)


class EvidenceCreateRequest(BaseModel):
    """Body for creating an evidence record."""

    finding_id: str
    data: str = Field(..., max_length=1_048_576)  # 1 MiB
    user: str = "anonymous"


class EvidenceAccessRequest(BaseModel):
    """Body for logging evidence access."""

    user: str = "anonymous"
    details: str = "Evidence accessed for review"


class EvidenceModifyRequest(BaseModel):
    """Body for modifying evidence data."""

    new_data: str
    user: str = "anonymous"
    details: str = "Evidence modified"


@router.get(
    "",
    response_model=list[dict[str, Any]],
    responses={401: {"model": ErrorResponse}},
    summary="List all evidence records",
)
async def list_evidence(
    limit: int = Query(200, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    finding_id: str | None = None,
    _auth: Any = Depends(require_auth),
) -> list[dict[str, Any]]:
    """Return evidence records, optionally filtered by finding_id."""
    _load_evidence_from_disk()
    with _evidence_lock:
        records = list(_evidence_records)

    if finding_id:
        records = [r for r in records if r.get("finding_id") == finding_id]

    # Most recent first
    records.sort(key=lambda r: r.get("created_at", ""), reverse=True)
    return records[offset : offset + limit]


@router.get(
    "/{evidence_id}",
    response_model=dict[str, Any],
    responses={401: {"model": ErrorResponse}, 404: {"model": ErrorResponse}},
    summary="Get a single evidence record",
)
async def get_evidence(
    evidence_id: str,
    _auth: Any = Depends(require_auth),
) -> dict[str, Any]:
    """Return a single evidence record by ID."""
    _load_evidence_from_disk()
    with _evidence_lock:
        for record in _evidence_records:
            if record["id"] == evidence_id:
                return record
    raise HTTPException(status_code=404, detail="Evidence record not found")


@router.post(
    "",
    response_model=dict[str, Any],
    responses={401: {"model": ErrorResponse}},
    summary="Create an evidence record",
)
async def create_evidence(
    payload: EvidenceCreateRequest,
    _auth: Any = Depends(require_auth),
) -> dict[str, Any]:
    """Create a new evidence record with an initial custody entry."""
    _load_evidence_from_disk()
    evidence_hash = _sha256(payload.data)
    record_id = f"evidence-{uuid.uuid4()}"
    now = datetime.now(UTC).isoformat()

    custody_entry = {
        "id": f"custody-{uuid.uuid4()}",
        "evidence_id": record_id,
        "action": "created",
        "user": payload.user,
        "timestamp": now,
        "hash_after": evidence_hash,
        "details": "Evidence created and hashed",
    }

    record = {
        "id": record_id,
        "finding_id": payload.finding_id,
        "data": payload.data,
        "hash": evidence_hash,
        "created_at": now,
        "created_by": payload.user,
        "custody_chain": [custody_entry],
    }

    with _evidence_lock:
        _evidence_records.append(record)
    _persist_evidence_to_disk()

    return record


@router.post(
    "/{evidence_id}/access",
    response_model=dict[str, Any],
    responses={401: {"model": ErrorResponse}, 404: {"model": ErrorResponse}},
    summary="Log evidence access",
)
async def log_evidence_access(
    evidence_id: str,
    payload: EvidenceAccessRequest,
    _auth: Any = Depends(require_auth),
) -> dict[str, Any]:
    """Append an 'accessed' entry to the custody chain."""
    _load_evidence_from_disk()
    authenticated_user = (_auth or {}).get("user", "anonymous")
    with _evidence_lock:
        for record in _evidence_records:
            if record["id"] == evidence_id:
                entry = {
                    "id": f"custody-{uuid.uuid4()}",
                    "evidence_id": evidence_id,
                    "action": "accessed",
                    "user": authenticated_user,
                    "timestamp": datetime.now(UTC).isoformat(),
                    "details": payload.details,
                }
                record["custody_chain"].append(entry)
                _persist_evidence_to_disk()
                return record
    raise HTTPException(status_code=404, detail="Evidence record not found")


@router.post(
    "/{evidence_id}/modify",
    response_model=dict[str, Any],
    responses={401: {"model": ErrorResponse}, 404: {"model": ErrorResponse}},
    summary="Modify evidence data",
)
async def modify_evidence(
    evidence_id: str,
    payload: EvidenceModifyRequest,
    _auth: Any = Depends(require_auth),
) -> dict[str, Any]:
    """Update evidence data and append a 'modified' custody entry."""
    _load_evidence_from_disk()
    authenticated_user = (_auth or {}).get("user", "anonymous")
    with _evidence_lock:
        for record in _evidence_records:
            if record["id"] == evidence_id:
                hash_before = record["hash"]
                hash_after = _sha256(payload.new_data)

                record["data"] = payload.new_data
                record["hash"] = hash_after

                entry = {
                    "id": f"custody-{uuid.uuid4()}",
                    "evidence_id": evidence_id,
                    "action": "modified",
                    "user": authenticated_user,
                    "timestamp": datetime.now(UTC).isoformat(),
                    "hash_before": hash_before,
                    "hash_after": hash_after,
                    "details": payload.details,
                }
                record["custody_chain"].append(entry)
                _persist_evidence_to_disk()
                return record
    raise HTTPException(status_code=404, detail="Evidence record not found")


@router.get(
    "/{evidence_id}/verify",
    response_model=dict[str, Any],
    responses={401: {"model": ErrorResponse}, 404: {"model": ErrorResponse}},
    summary="Verify evidence integrity",
)
async def verify_evidence(
    evidence_id: str,
    _auth: Any = Depends(require_auth),
) -> dict[str, Any]:
    """Verify that the stored hash matches the current data."""
    _load_evidence_from_disk()
    with _evidence_lock:
        for record in _evidence_records:
            if record["id"] == evidence_id:
                current_hash = _sha256(record["data"])
                valid = current_hash == record["hash"]
                return {
                    "valid": valid,
                    "message": "Evidence integrity verified"
                    if valid
                    else "Evidence integrity compromised - hash mismatch!",
                    "stored_hash": record["hash"],
                    "computed_hash": current_hash,
                }
    raise HTTPException(status_code=404, detail="Evidence record not found")


@router.delete(
    "/{evidence_id}",
    responses={401: {"model": ErrorResponse}, 404: {"model": ErrorResponse}},
    summary="Delete an evidence record",
)
async def delete_evidence(
    evidence_id: str,
    payload: EvidenceAccessRequest,
    _auth: Any = Depends(require_auth),
) -> dict[str, str]:
    """Remove an evidence record after recording a custody entry."""
    global _evidence_records
    _load_evidence_from_disk()
    with _evidence_lock:
        for record in _evidence_records:
            if record["id"] == evidence_id:
                custody_entry = {
                    "id": f"custody-{uuid.uuid4()}",
                    "evidence_id": evidence_id,
                    "action": "deleted",
                    "user": payload.user,
                    "timestamp": datetime.now(UTC).isoformat(),
                    "hash_before": record.get("hash"),
                    "details": "Evidence record deleted",
                }
                record["custody_chain"].append(custody_entry)
                _evidence_records = [r for r in _evidence_records if r["id"] != evidence_id]
                _persist_evidence_to_disk()
                return {"status": "deleted"}
    raise HTTPException(status_code=404, detail="Evidence record not found")
