"""Request replay endpoint for the FastAPI dashboard."""

import json
import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from src.core.security import reject_if_query_contains_credentials
from src.dashboard.fastapi.dependencies import get_queue_client, require_auth
from src.dashboard.fastapi.schemas import ErrorResponse, ReplayResponse
from src.dashboard.fastapi.validation import (
    is_safe_replay_url,
    is_within_directory,
    validate_replay_id,
    validate_run_name,
    validate_target_name,
)

router = APIRouter(prefix="/api/replay", tags=["Replay"])


logger = logging.getLogger(__name__)


def _reject_sensitive_query_params(request: Request) -> None:
    """Reject requests that pass credentials via query string.

    Tokens in query params get logged in access logs and stored in browser
    history / proxy caches, so they must never be the primary auth path.
    The authoritative list of sensitive names lives in
    :mod:`src.core.security.sensitive_names`.
    """
    leaked = reject_if_query_contains_credentials(request.query_params)
    if leaked:
        raise HTTPException(
            status_code=400,
            detail=(
                "Sensitive credentials must not be supplied as query parameters. "
                f"Remove parameter(s): {', '.join(leaked)}."
            ),
        )


@router.get(
    "",
    response_model=ReplayResponse,
    responses={
        400: {"model": ErrorResponse},
        404: {"model": ErrorResponse},
        401: {"model": ErrorResponse},
    },
    summary="Replay a captured request",
)
async def replay_request(
    request: Request,
    target: str = Query(..., description="Target name"),
    run: str = Query(..., description="Run name"),
    replay_id: str = Query(..., description="Replay ID"),
    auth_mode: str = Query("inherit", description="Authentication mode"),
    # ``authorization`` / ``cookie`` are accepted as explicit query
    # parameters so callers can force the replay into ``anonymous`` or
    # ``bearer`` mode without depending on the inbound ``Request``
    # headers. They are NOT used to bypass authentication on this
    # endpoint; they only feed ``replay_headers_for_mode`` for the
    # outbound replay request.
    authorization: str = Query("", description="Bearer token for bearer mode"),
    cookie: str = Query("", description="Cookie value to forward to the replay target"),
    _auth: Any = Depends(require_auth),
    services: Any = Depends(get_queue_client),
) -> ReplayResponse:
    """Replay a previously captured request and compare responses."""
    # Refuse to even process the request if the caller put credentials in
    # the URL; this stops the leak before any handler logic runs. The
    # guard is a no-op when the function is invoked outside an HTTP
    # context (e.g. unit tests that drive the handler directly).
    if request is not None:
        _reject_sensitive_query_params(request)

    if not validate_target_name(target):
        raise HTTPException(status_code=400, detail="Invalid target name.")
    if not validate_run_name(run):
        raise HTTPException(status_code=400, detail="Invalid run name.")
    if not validate_replay_id(replay_id):
        raise HTTPException(status_code=400, detail="Invalid replay ID.")

    from src.core.contracts.protocol_registry import get_exploit_replay

    replay_headers_for_mode = get_exploit_replay()
    if replay_headers_for_mode is None:
        try:
            from src.bootstrap.startup_registration import ensure_protocol_bindings_registered

            ensure_protocol_bindings_registered()
            replay_headers_for_mode = get_exploit_replay()
        except Exception:
            pass

    if replay_headers_for_mode is None:
        try:
            from src.execution.exploiters.exploit_automation import (
                replay_headers_for_mode as _r_headers,
            )

            replay_headers_for_mode = _r_headers
        except Exception:
            raise HTTPException(status_code=500, detail="Exploit replay protocol not available")

    # Never copy the dashboard's inbound Authorization/Cookie onto the
    # target. Replay credentials must come from the stored request
    # context (inherit) or an explicit body — query params are rejected
    # above as a credential leak.
    extra_authorization = ""
    extra_cookie = ""
    _ = (authorization, cookie)
    try:
        extra_headers = replay_headers_for_mode(
            auth_mode,
            authorization=extra_authorization,
            cookie=extra_cookie,
        )
    except ValueError as exc:
        logger.exception("Replay header generation failed: %s", exc)
        raise HTTPException(status_code=400, detail=str(exc))

    from src.core.contracts.protocol_registry import (
        get_fetch_response_provider,
        get_plugin_artifact_loader,
        get_response_comparator,
    )

    compare_response_records = get_response_comparator()
    artifact_loader = get_plugin_artifact_loader()
    fetch_response_provider = get_fetch_response_provider()

    if fetch_response_provider is None:
        try:
            from src.bootstrap.startup_registration import ensure_protocol_bindings_registered

            ensure_protocol_bindings_registered()
            fetch_response_provider = get_fetch_response_provider()
            artifact_loader = get_plugin_artifact_loader()
            compare_response_records = get_response_comparator()
        except Exception:
            pass

    if fetch_response_provider is None:
        try:
            from src.analysis.passive.runtime import _get_fetch_response

            fetch_response_provider = _get_fetch_response
        except Exception:
            raise HTTPException(status_code=500, detail="Fetch response provider not available")

    fetch_response = fetch_response_provider()

    output_root = services.query.output_root.resolve()
    run_dir = (output_root / target / run).resolve()
    if not is_within_directory(output_root, run_dir):
        raise HTTPException(status_code=404, detail="Replay context not found.")

    if artifact_loader is not None and hasattr(artifact_loader, "plugin_artifact_path"):
        try:
            behavior_path = artifact_loader.plugin_artifact_path(
                run_dir, "behavior_analysis_layer"
            ).resolve()
        except Exception:
            behavior_path = (run_dir / "analysis_plugins" / "behavior_analysis.json").resolve()
    else:
        behavior_path = (run_dir / "analysis_plugins" / "behavior_analysis.json").resolve()
    legacy_path = (run_dir / "behavior_analysis_layer.json").resolve()

    if is_within_directory(output_root, behavior_path) and not behavior_path.exists():
        # Fall back to checking legacy or alternate plugin path
        alt_path = (run_dir / "analysis_plugins" / "behavior_analysis_layer.json").resolve()
        if alt_path.exists():
            behavior_path = alt_path

    records: list[Any] | None = None
    if behavior_path.exists():
        try:
            records = json.loads(behavior_path.read_text(encoding="utf-8"))
        except Exception:
            records = None

    if (records is None or len(records) == 0) and legacy_path.exists():
        try:
            records = json.loads(legacy_path.read_text(encoding="utf-8"))
        except Exception:
            records = None

    if (
        (records is None or len(records) == 0)
        and artifact_loader is not None
        and hasattr(artifact_loader, "load_plugin_artifact")
    ):
        try:
            records = artifact_loader.load_plugin_artifact(run_dir, "behavior_analysis_layer")
        except Exception:
            records = None

    if isinstance(records, dict):
        records = [records]

    if records is None or not isinstance(records, list) or len(records) == 0:
        raise HTTPException(status_code=404, detail="Replay context not found.")

    item = next(
        (entry for entry in records if str(entry.get("replay", {}).get("id", "")) == replay_id),
        None,
    )
    if not isinstance(item, dict):
        raise HTTPException(status_code=404, detail="Replay id not found.")

    request_context = item.get("request_context", {})
    baseline_url = str(request_context.get("baseline_url", "")).strip()
    mutated_url = str(request_context.get("mutated_url", "")).strip()

    if not mutated_url:
        raise HTTPException(status_code=400, detail="Stored request context is incomplete.")

    if baseline_url and not is_safe_replay_url(baseline_url):
        raise HTTPException(status_code=400, detail="Replay URL targets a restricted network.")
    if not is_safe_replay_url(mutated_url):
        raise HTTPException(status_code=400, detail="Replay URL targets a restricted network.")

    try:
        baseline = (
            fetch_response(
                baseline_url, timeout_seconds=12, max_bytes=120000, extra_headers=extra_headers
            )
            if baseline_url
            else None
        )
    except Exception as exc:
        logger.warning("Baseline fetch failed for replay %s: %s", replay_id, exc)
        baseline = None

    try:
        replay = fetch_response(
            mutated_url, timeout_seconds=12, max_bytes=120000, extra_headers=extra_headers
        )
    except Exception as exc:
        logger.warning("Replay fetch failed for %s: %s", replay_id, exc)
        raise HTTPException(status_code=502, detail=str(exc))

    if not replay:
        raise HTTPException(status_code=502, detail="Replay request did not return a response.")

    if compare_response_records is None:
        try:
            from src.analysis.behavior.analysis_support import compare_response_records as _comp

            compare_response_records = _comp
        except Exception:

            def compare_response_records(b, r):  # type: ignore[misc]
                """Fallback when the behaviour-analysis module is unavailable."""
                return {}

    diff = compare_response_records(baseline, replay) if baseline else {}

    return ReplayResponse(
        replay_id=replay_id,
        auth_mode=auth_mode,
        applied_header_names=sorted(extra_headers),
        requested_url=replay.get("requested_url", mutated_url),
        final_url=replay.get("url", mutated_url),
        redirect_chain=replay.get("redirect_chain", []),
        status_code=replay.get("status_code"),
        body_similarity=diff.get("body_similarity"),
        status_changed=diff.get("status_changed"),
        redirect_changed=diff.get("redirect_changed"),
        content_changed=diff.get("content_changed"),
    )
