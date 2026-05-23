"""Collaborative triage REST and WebSocket endpoints."""

from __future__ import annotations

import json
from typing import Any, cast

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Query,
    Request,
    WebSocket,
    WebSocketDisconnect,
)

from src.dashboard.fastapi.collaboration import TriageCollaborationService, TriageConnection
from src.dashboard.fastapi.dependencies import require_auth
from src.learning.integration import LearningIntegration

router = APIRouter(prefix="/api/triage", tags=["Triage Collaboration"])


def get_triage_service(request: Request) -> TriageCollaborationService:
    service = getattr(request.app.state, "triage_collaboration", None)
    if service is None:
        config = request.app.state.config
        service = TriageCollaborationService(config.output_root)
        request.app.state.triage_collaboration = service
    return service


@router.get("/runs/{run_id}/findings/{finding_id}")
async def get_finding_triage_state(
    run_id: str,
    finding_id: str,
    _auth: Any = Depends(require_auth),
    service: TriageCollaborationService = Depends(get_triage_service),
) -> dict[str, Any]:
    return service.build_finding_state(run_id, finding_id)


@router.get("/runs/{run_id}/audit")
async def get_triage_audit(
    run_id: str,
    finding_id: str | None = None,
    limit: int = Query(200, ge=1, le=1000),
    _auth: Any = Depends(require_auth),
    service: TriageCollaborationService = Depends(get_triage_service),
) -> dict[str, Any]:
    return {
        "events": service.list_events(run_id=run_id, finding_id=finding_id, limit=limit),
        "chain": service.verify_chain(),
    }


@router.get("/audit/verify")
async def verify_triage_audit(
    _auth: Any = Depends(require_auth),
    service: TriageCollaborationService = Depends(get_triage_service),
) -> dict[str, Any]:
    return service.verify_chain()


@router.post("/runs/{run_id}/findings/{finding_id}/actions")
async def record_triage_action(
    run_id: str,
    finding_id: str,
    payload: dict[str, Any],
    auth: Any = Depends(require_auth),
    service: TriageCollaborationService = Depends(get_triage_service),
) -> dict[str, Any]:
    action = str(payload.get("action") or "")
    analyst_id = str(payload.get("analyst_id") or auth.get("user") or "analyst")
    analyst_name = str(payload.get("analyst_name") or analyst_id)
    event_payload = (
        cast(dict[str, Any], payload.get("payload"))
        if isinstance(payload.get("payload"), dict)
        else {}
    )
    try:
        event = service.record_action(
            run_id=run_id,
            finding_id=finding_id,
            action=action,
            analyst_id=analyst_id,
            analyst_name=analyst_name,
            payload=event_payload,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    if action == "finding_false_positive":
        await _register_false_positive_pattern(finding_id, event_payload)

    await service.broadcast(
        run_id,
        {
            "type": "triage_event",
            "event": event,
            "state": service.build_finding_state(run_id, finding_id),
        },
    )
    return {"event": event, "state": service.build_finding_state(run_id, finding_id)}


async def _register_false_positive_pattern(finding_id: str, payload: dict[str, Any]) -> None:
    try:
        learning = LearningIntegration.get_or_create()
        if not learning.config.enabled:
            return
        status_code = payload.get("status_code") or payload.get("response_status")
        await learning._fp_tracker.add_manual_fp(
            category=str(payload.get("category") or payload.get("module") or "manual_triage"),
            status_code=int(status_code) if status_code else None,
            body_indicator=str(
                payload.get("body_indicator")
                or payload.get("evidence")
                or payload.get("description")
                or finding_id
            ),
        )
    except Exception:
        return


async def handle_triage_websocket(
    websocket: WebSocket,
    run_id: str,
    service: TriageCollaborationService,
) -> None:
    analyst_id = websocket.query_params.get("analyst_id") or "anonymous"
    analyst_name = websocket.query_params.get("analyst_name") or analyst_id
    await websocket.accept()
    connection = TriageConnection(
        websocket=websocket,
        run_id=run_id,
        analyst_id=analyst_id,
        analyst_name=analyst_name,
    )
    await service.connect(connection)
    await websocket.send_text(
        json.dumps(
            {
                "type": "connected",
                "run_id": run_id,
                "connection_id": connection.connection_id,
                "chain": service.verify_chain(),
            }
        )
    )

    try:
        while True:
            raw = await websocket.receive_text()
            message = json.loads(raw)
            msg_type = str(message.get("type") or "")
            if msg_type in {"presence", "cursor"}:
                await service.update_presence(
                    run_id,
                    connection.connection_id,
                    finding_id=message.get("finding_id"),
                    cursor=message.get("cursor") if isinstance(message.get("cursor"), dict) else {},
                )
            elif msg_type == "triage_action":
                finding_id = str(message.get("finding_id") or "")
                action = str(message.get("action") or "")
                event_payload = (
                    message.get("payload") if isinstance(message.get("payload"), dict) else {}
                )
                event = service.record_action(
                    run_id=run_id,
                    finding_id=finding_id,
                    action=action,
                    analyst_id=connection.analyst_id,
                    analyst_name=connection.analyst_name,
                    payload=event_payload,
                )
                if action == "finding_false_positive":
                    await _register_false_positive_pattern(finding_id, event_payload)
                await service.broadcast(
                    run_id,
                    {
                        "type": "triage_event",
                        "event": event,
                        "state": service.build_finding_state(run_id, finding_id),
                    },
                )
    except WebSocketDisconnect, json.JSONDecodeError:
        pass
    finally:
        await service.disconnect(run_id, connection.connection_id)
