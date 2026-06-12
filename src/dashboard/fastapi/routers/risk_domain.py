"""Modern risk domain endpoints.

Provides CRUD + query endpoints for:

* ``assets`` – the structured asset registry used by the
  ``AssetRegistry`` and ``AssetCriticalityService``.
* ``risk_acceptances`` – governance workflow for formally accepting
  risk on a finding for a defined window.
* ``compensating_controls`` – controls that reduce effective severity
  via the ``CompensatingControlEngine``.
* ``sla_events`` – lifecycle state transitions and per-stage lag
  queries from ``FindingLifecycleManager``.
* ``reviewer_actions`` – structured-review log emitted from the
  ``FindingReviewPanel`` UI.

All endpoints are read-only by default; mutations require the
``require_admin`` dependency. A best-effort ``_get_store`` helper
falls back to a fresh :class:`TelemetryStore` instance when the
``LearningIntegration`` is not initialised (so the router works in
test/dev environments without booting the rest of the dashboard).
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
from src.intelligence.risk.finding_lifecycle import (
    FindingLifecycleManager,
    FindingState,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/risk-domain", tags=["Risk Domain"])


_VALID_ASSET_COLUMNS = frozenset(
    {
        "asset_id",
        "name",
        "host_pattern",
        "path_prefix",
        "asset_type",
        "entity_type",
        "criticality",
        "tier",
        "business_value",
        "compliance_requirements",
        "owner",
        "notes",
        "metadata",
        "is_active",
    }
)

_VALID_ACCEPTANCE_COLUMNS = frozenset(
    {
        "acceptance_id",
        "finding_id",
        "asset_id",
        "accepted_until",
        "accepted_by",
        "justification",
        "compensating_control_ref",
        "review_date",
        "scope",
        "state",
        "created_by",
        "metadata",
    }
)

_VALID_CONTROL_COLUMNS = frozenset(
    {
        "control_id",
        "finding_id",
        "control_type",
        "description",
        "discount_factor",
        "evidence_url",
        "owner",
        "expires_at",
        "is_active",
        "metadata",
    }
)


def _nested_get(data: dict[str, Any], *keys: str, default: Any = None) -> Any:
    """Safely traverse nested dicts: _nested_get(d, 'a', 'b') is d.get('a', {}).get('b')."""
    current: Any = data
    for key in keys:
        if not isinstance(current, dict):
            return default
        current = current.get(key, default)
    return current


# ---------------------------------------------------------------------------
# Store / connection helpers
# ---------------------------------------------------------------------------


def _get_store(request: Request) -> Any:
    """Resolve the active :class:`TelemetryStore` from app state.

    Falls back to a freshly created ``TelemetryStore`` instance
    pointed at the integration's database path when the global
    integration isn't wired up yet. This keeps the router testable
    in isolation.
    """
    services = getattr(request.app.state, "services", None)
    if services is not None and hasattr(services, "store"):
        store = services.store
        if not getattr(store, "_initialized", False):
            store.initialize()
        return store
    from src.learning.repositories.telemetry_store import TelemetryStore

    fallback = TelemetryStore()
    fallback.initialize()
    return fallback


def _row_to_dict(cursor: sqlite3.Cursor, row: tuple) -> dict[str, Any]:
    return {col[0]: row[idx] for idx, col in enumerate(cursor.description)}


# ---------------------------------------------------------------------------
# Assets
# ---------------------------------------------------------------------------


@router.get("/assets", summary="List registered assets")
async def list_assets(
    request: Request,
    asset_type: str | None = None,
    active_only: bool = True,
    limit: int = Query(200, ge=1, le=2000),
    _auth: Any = Depends(require_auth),
) -> list[dict[str, Any]]:
    store = _get_store(request)
    query = "SELECT asset_id, name, host_pattern, path_prefix, asset_type, entity_type, criticality, tier, business_value, compliance_requirements, owner, notes, metadata, is_active, created_at, updated_at FROM assets"
    clauses: list[str] = []
    params: list[Any] = []
    if active_only:
        clauses.append("is_active = 1")
    if asset_type:
        clauses.append("asset_type = ?")
        params.append(asset_type)
    if clauses:
        query += " WHERE " + " AND ".join(clauses)
    query += " ORDER BY criticality DESC, name LIMIT ?"
    params.append(limit)
    conn = store._get_conn()
    cursor = conn.execute(query, params)
    return [_row_to_dict(cursor, row) for row in cursor.fetchall()]


@router.post("/assets", summary="Create a new asset", dependencies=[Depends(require_admin)])
async def create_asset(
    request: Request,
    payload: dict[str, Any],
) -> dict[str, Any]:
    name = str(payload.get("name") or "").strip()
    host_pattern = str(payload.get("host_pattern") or "").strip()
    if not name or not host_pattern:
        raise HTTPException(status_code=422, detail="name and host_pattern are required")
    asset_id = str(payload.get("asset_id") or f"asset-{uuid.uuid4().hex[:12]}")
    record = {
        "asset_id": asset_id,
        "name": name,
        "host_pattern": host_pattern,
        "path_prefix": payload.get("path_prefix"),
        "asset_type": str(payload.get("asset_type") or "unknown"),
        "entity_type": str(payload.get("entity_type") or "unknown"),
        "criticality": float(payload.get("criticality") or 1.0),
        "tier": str(payload.get("tier") or "tier_4"),
        "business_value": float(payload.get("business_value") or 1.0),
        "compliance_requirements": payload.get("compliance_requirements"),
        "owner": payload.get("owner"),
        "notes": payload.get("notes"),
        "metadata": json.dumps(payload.get("metadata") or {}),
        "is_active": 1 if payload.get("is_active", True) else 0,
    }
    store = _get_store(request)
    conn = store._get_conn()
    try:
        conn.execute(
            "INSERT OR REPLACE INTO assets "
            "(asset_id, name, host_pattern, path_prefix, asset_type, entity_type, criticality, "
            "tier, business_value, compliance_requirements, owner, notes, metadata, is_active) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                record["asset_id"],
                record["name"],
                record["host_pattern"],
                record["path_prefix"],
                record["asset_type"],
                record["entity_type"],
                record["criticality"],
                record["tier"],
                record["business_value"],
                record["compliance_requirements"],
                record["owner"],
                record["notes"],
                record["metadata"],
                record["is_active"],
            ],
        )
        conn.commit()
    except sqlite3.OperationalError as exc:
        conn.rollback()
        raise HTTPException(status_code=500, detail=f"Database error: {exc}") from exc
    return {"asset_id": asset_id, "status": "created"}


@router.delete(
    "/assets/{asset_id}", summary="Delete an asset", dependencies=[Depends(require_admin)]
)
async def delete_asset(asset_id: str, request: Request) -> dict[str, Any]:
    store = _get_store(request)
    conn = store._get_conn()
    cursor = conn.execute("DELETE FROM assets WHERE asset_id = ?", [asset_id])
    conn.commit()
    return {"asset_id": asset_id, "deleted_rows": cursor.rowcount}


# ---------------------------------------------------------------------------
# Risk acceptances
# ---------------------------------------------------------------------------


@router.get("/acceptances", summary="List risk acceptances")
async def list_acceptances(
    request: Request,
    state: str | None = None,
    finding_id: str | None = None,
    limit: int = Query(200, ge=1, le=2000),
    _auth: Any = Depends(require_auth),
) -> list[dict[str, Any]]:
    query = "SELECT acceptance_id, finding_id, asset_id, accepted_until, accepted_by, justification, compensating_control_ref, review_date, scope, state, created_by, metadata, created_at, updated_at FROM risk_acceptances"
    clauses: list[str] = []
    params: list[Any] = []
    if state:
        clauses.append("state = ?")
        params.append(state)
    if finding_id:
        clauses.append("finding_id = ?")
        params.append(finding_id)
    if clauses:
        query += " WHERE " + " AND ".join(clauses)
    query += " ORDER BY created_at DESC LIMIT ?"
    params.append(limit)
    store = _get_store(request)
    conn = store._get_conn()
    cursor = conn.execute(query, params)
    return [_row_to_dict(cursor, row) for row in cursor.fetchall()]


@router.post(
    "/acceptances",
    summary="Create a risk acceptance",
    dependencies=[Depends(require_admin)],
)
async def create_acceptance(
    request: Request,
    payload: dict[str, Any],
) -> dict[str, Any]:
    finding_id = str(payload.get("finding_id") or "").strip()
    if not finding_id:
        raise HTTPException(status_code=422, detail="finding_id is required")
    acceptance_id = str(payload.get("acceptance_id") or f"acc-{uuid.uuid4().hex[:12]}")
    record = {
        "acceptance_id": acceptance_id,
        "finding_id": finding_id,
        "asset_id": payload.get("asset_id"),
        "accepted_until": payload.get("accepted_until"),
        "accepted_by": str(payload.get("accepted_by") or "unknown"),
        "justification": str(payload.get("justification") or ""),
        "compensating_control_ref": payload.get("compensating_control_ref"),
        "review_date": payload.get("review_date"),
        "scope": str(payload.get("scope") or "global"),
        "state": str(payload.get("state") or "active"),
        "created_by": payload.get("created_by"),
        "metadata": json.dumps(payload.get("metadata") or {}),
    }
    store = _get_store(request)
    conn = store._get_conn()
    conn.execute(
        "INSERT OR REPLACE INTO risk_acceptances "
        "(acceptance_id, finding_id, asset_id, accepted_until, accepted_by, justification, "
        "compensating_control_ref, review_date, scope, state, created_by, metadata) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        [
            record["acceptance_id"],
            record["finding_id"],
            record["asset_id"],
            record["accepted_until"],
            record["accepted_by"],
            record["justification"],
            record["compensating_control_ref"],
            record["review_date"],
            record["scope"],
            record["state"],
            record["created_by"],
            record["metadata"],
        ],
    )
    conn.commit()
    return {"acceptance_id": acceptance_id, "status": "created"}


@router.post(
    "/acceptances/{acceptance_id}/revoke",
    summary="Revoke a previously accepted risk",
    dependencies=[Depends(require_admin)],
)
async def revoke_acceptance(acceptance_id: str, request: Request) -> dict[str, Any]:
    store = _get_store(request)
    conn = store._get_conn()
    conn.execute(
        "UPDATE risk_acceptances SET state = 'revoked', updated_at = CURRENT_TIMESTAMP "
        "WHERE acceptance_id = ?",
        [acceptance_id],
    )
    conn.commit()
    return {"acceptance_id": acceptance_id, "state": "revoked"}


# ---------------------------------------------------------------------------
# Compensating controls
# ---------------------------------------------------------------------------


@router.get("/controls", summary="List compensating controls")
async def list_controls(
    request: Request,
    finding_id: str | None = None,
    control_type: str | None = None,
    active_only: bool = True,
    limit: int = Query(200, ge=1, le=2000),
    _auth: Any = Depends(require_auth),
) -> list[dict[str, Any]]:
    query = "SELECT control_id, finding_id, control_type, description, discount_factor, evidence_url, owner, expires_at, is_active, metadata, created_at, updated_at FROM compensating_controls"
    clauses: list[str] = []
    params: list[Any] = []
    if active_only:
        clauses.append("is_active = 1")
    if finding_id:
        clauses.append("finding_id = ?")
        params.append(finding_id)
    if control_type:
        clauses.append("control_type = ?")
        params.append(control_type)
    if clauses:
        query += " WHERE " + " AND ".join(clauses)
    query += " ORDER BY created_at DESC LIMIT ?"
    params.append(limit)
    store = _get_store(request)
    conn = store._get_conn()
    cursor = conn.execute(query, params)
    return [_row_to_dict(cursor, row) for row in cursor.fetchall()]


@router.post(
    "/controls",
    summary="Add a compensating control",
    dependencies=[Depends(require_admin)],
)
async def create_control(
    request: Request,
    payload: dict[str, Any],
) -> dict[str, Any]:
    finding_id = str(payload.get("finding_id") or "").strip()
    control_type = str(payload.get("control_type") or "").strip()
    if not finding_id or not control_type:
        raise HTTPException(status_code=422, detail="finding_id and control_type are required")
    control_id = str(payload.get("control_id") or f"ctrl-{uuid.uuid4().hex[:12]}")
    record = {
        "control_id": control_id,
        "finding_id": finding_id,
        "control_type": control_type,
        "description": payload.get("description"),
        "discount_factor": float(payload.get("discount_factor") or 0.85),
        "evidence_url": payload.get("evidence_url"),
        "owner": payload.get("owner"),
        "expires_at": payload.get("expires_at"),
        "is_active": 1 if payload.get("is_active", True) else 0,
        "metadata": json.dumps(payload.get("metadata") or {}),
    }
    store = _get_store(request)
    conn = store._get_conn()
    conn.execute(
        "INSERT OR REPLACE INTO compensating_controls "
        "(control_id, finding_id, control_type, description, discount_factor, evidence_url, "
        "owner, expires_at, is_active, metadata) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        [
            record["control_id"],
            record["finding_id"],
            record["control_type"],
            record["description"],
            record["discount_factor"],
            record["evidence_url"],
            record["owner"],
            record["expires_at"],
            record["is_active"],
            record["metadata"],
        ],
    )
    conn.commit()
    return {"control_id": control_id, "status": "created"}


# ---------------------------------------------------------------------------
# Finding review
# ---------------------------------------------------------------------------


@router.post(
    "/findings/{finding_id}/review",
    summary="Record a structured reviewer action (FindingReviewPanel)",
    dependencies=[Depends(require_admin)],
)
async def record_reviewer_action(
    finding_id: str,
    request: Request,
    payload: dict[str, Any],
) -> dict[str, Any]:
    action_type = str(payload.get("action_type") or "").strip()
    if action_type not in {
        "confirm_tp",
        "dismiss_fp",
        "downgrade_severity",
        "upgrade_severity",
        "request_validation",
        "assign_owner",
    }:
        raise HTTPException(
            status_code=422,
            detail=f"action_type must be one of the supported values, got '{action_type}'",
        )
    reviewer_id = str(payload.get("reviewer_id") or "unknown")
    action_id = f"ra-{uuid.uuid4().hex[:12]}"
    store = _get_store(request)
    conn = store._get_conn()
    conn.execute(
        "INSERT INTO reviewer_actions "
        "(action_id, finding_id, action_type, reviewer_id, structured_note, "
        " from_state, to_state, timestamp, metadata) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        [
            action_id,
            finding_id,
            action_type,
            reviewer_id,
            payload.get("structured_note"),
            payload.get("from_state"),
            payload.get("to_state"),
            payload.get("timestamp") or time.time(),
            json.dumps(payload.get("metadata") or {}),
        ],
    )
    # Emit a feedback event so the active-learning loop can pick the
    # override up with ``override_source=analyst_triage``.
    try:
        conn.execute(
            "INSERT INTO feedback_events "
            "(feedback_id, finding_id, run_id, reviewer_id, override_source, "
            " was_validated, was_false_positive, override_reason, finding_severity, "
            " finding_category, plugin_name, asset_type, feedback_weight, timestamp) "
            "VALUES (?, ?, ?, ?, 'analyst_triage', ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                f"fb-{uuid.uuid4().hex[:12]}",
                finding_id,
                payload.get("run_id") or "manual",
                reviewer_id,
                1 if action_type == "confirm_tp" else 0,
                1 if action_type == "dismiss_fp" else 0,
                payload.get("structured_note") or "",
                payload.get("finding_severity") or "unknown",
                payload.get("finding_category") or "unknown",
                payload.get("plugin_name") or "manual_review",
                payload.get("asset_type") or "unknown",
                2.0,  # analyst weight (matches severity_model/active_learning policy)
                time.time(),
            ],
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("Failed to record feedback for reviewer action %s: %s", action_id, exc)
    conn.commit()
    return {"action_id": action_id, "status": "recorded"}


@router.get(
    "/findings/{finding_id}/review-history",
    summary="Get the structured-review history for a finding",
)
async def get_review_history(
    finding_id: str,
    request: Request,
    _auth: Any = Depends(require_auth),
) -> list[dict[str, Any]]:
    store = _get_store(request)
    conn = store._get_conn()
    cursor = conn.execute(
        "SELECT * FROM reviewer_actions WHERE finding_id = ? ORDER BY timestamp DESC LIMIT 200",
        [finding_id],
    )
    return [_row_to_dict(cursor, row) for row in cursor.fetchall()]


# ---------------------------------------------------------------------------
# SLA / lifecycle
# ---------------------------------------------------------------------------


@router.get(
    "/sla/summary",
    summary="Get lifecycle SLA summary (avg/worst per-stage lag, breaches)",
)
async def get_sla_summary(
    request: Request,
    days: int = Query(30, ge=1, le=365),
    _auth: Any = Depends(require_auth),
) -> dict[str, Any]:
    """Return aggregate per-stage SLA metrics.

    The summary is derived from the ``sla_events`` table, not from
    the live state of individual findings, so it can answer historical
    questions (e.g. "how long did triage take in the past N days?")
    without re-walking the entire ``findings`` table.
    """
    store = _get_store(request)
    manager = FindingLifecycleManager()
    return manager.lifecycle_summary(  # type: ignore[attr-defined]
        conn=store._get_conn(),
        days=days,
    )


@router.get(
    "/findings/{finding_id}/lifecycle",
    summary="Get the lifecycle timeline for a single finding",
)
async def get_finding_lifecycle(
    finding_id: str,
    request: Request,
    _auth: Any = Depends(require_auth),
) -> list[dict[str, Any]]:
    store = _get_store(request)
    conn = store._get_conn()
    cursor = conn.execute(
        "SELECT * FROM sla_events WHERE finding_id = ? ORDER BY timestamp ASC",
        [finding_id],
    )
    return [_row_to_dict(cursor, row) for row in cursor.fetchall()]


@router.post(
    "/findings/{finding_id}/transition",
    summary="Record a lifecycle state transition for a finding",
    dependencies=[Depends(require_admin)],
)
async def transition_finding(
    finding_id: str,
    request: Request,
    payload: dict[str, Any],
) -> dict[str, Any]:
    from_state = str(payload.get("from_state") or "").strip()
    to_state = str(payload.get("to_state") or "").strip()
    if not to_state or to_state not in {state.value for state in FindingState}:
        raise HTTPException(
            status_code=422, detail="to_state must be one of the known FindingState values"
        )
    store = _get_store(request)
    conn = store._get_conn()
    event_id = f"sla-{uuid.uuid4().hex[:12]}"
    conn.execute(
        "INSERT INTO sla_events "
        "(event_id, finding_id, from_state, to_state, timestamp, actor, note, metadata) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        [
            event_id,
            finding_id,
            from_state or "unknown",
            to_state,
            payload.get("timestamp") or time.time(),
            payload.get("actor"),
            payload.get("note"),
            json.dumps(payload.get("metadata") or {}),
        ],
    )
    # Stamp the new state on the finding row so the rest of the
    # pipeline (sort/filter) can use it without re-walking the events
    # table.
    _VALID_TIMESTAMP_COLUMNS = {"triaged_at", "remediation_started_at", "fixed_at", "verified_at"}
    timestamp_col = {
        "triaged": "triaged_at",
        "in_remediation": "remediation_started_at",
        "fixed": "fixed_at",
        "verified": "verified_at",
    }.get(to_state)
    if timestamp_col and timestamp_col in _VALID_TIMESTAMP_COLUMNS:
        try:
            conn.execute(
                f"UPDATE findings SET {timestamp_col} = CURRENT_TIMESTAMP WHERE finding_id = ?",  # noqa: S608  # nosec
                [finding_id],
            )
        except Exception as exc:  # noqa: BLE001
            logger.debug("Failed to stamp %s on finding %s: %s", timestamp_col, finding_id, exc)
    conn.commit()
    return {"event_id": event_id, "finding_id": finding_id, "to_state": to_state}


__all__ = ["router"]
