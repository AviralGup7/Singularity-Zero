"""GraphQL abuse validator (R7).

Detects common GraphQL endpoint misconfigurations:
- Introspection enabled in production.
- Batching/alias amplification (multiple identical operations in one request).
- Excessive query depth (DoS via deeply nested queries).

The validator expects a ``graphql_request`` callable that performs a POST
request to a GraphQL endpoint with the supplied ``query`` and returns a
``{"status_code": int, "body": str, "headers": dict}`` dict.
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Callable
from typing import Any

from src.execution.validators.config.scoring_config import ScoringConfig
from src.execution.validators.status import ValidationStatus
from src.execution.validators.validators.shared import (
    bounded_confidence,
    to_validation_result,
)

logger = logging.getLogger(__name__)

INTROSPECTION_QUERY = (
    "{__schema{queryType{name}mutationType{name}subscriptionType{name}"
    "types{name}}}"
)

_DEPTH_PROBE_QUERY = (
    "{__schema{queryType{fields{type{ofType{ofType{ofType{ofType{ofType"
    "{ofType{ofType{ofType{ofType{name}}}}}}}}}}}}}"
)

BATCH_QUERY = "[{__typename},{__typename},{__typename},{__typename},{__typename}]"

_INTROSPECTION_MARKER = "__schema"


def _looks_like_introspection_response(body: str) -> bool:
    if not body:
        return False
    lowered = body.lower()
    return "__schema" in lowered and "querytype" in lowered


def _looks_like_batch_response(body: str) -> bool:
    if not body:
        return False
    try:
        parsed = json.loads(body)
    except (ValueError, TypeError):
        return False
    if isinstance(parsed, list) and len(parsed) >= 3:
        return all(isinstance(item, dict) and "data" in item for item in parsed)
    return False


def _count_nested_braces(query: str) -> int:
    """Return the maximum depth of nested braces in the GraphQL query."""
    depth = 0
    max_depth = 0
    for char in query:
        if char == "{":
            depth += 1
            max_depth = max(max_depth, depth)
        elif char == "}":
            depth -= 1
    return max_depth


def evaluate_graphql(
    *,
    endpoint: str,
    scoring: ScoringConfig,
    graphql_request: Callable[[str, str], dict[str, Any]] | None = None,
    introspection_query: str = INTROSPECTION_QUERY,
    depth_query: str = _DEPTH_PROBE_QUERY,
    batch_query: str = BATCH_QUERY,
    max_acceptable_depth: int = 8,
    in_scope: bool = True,
) -> dict[str, Any]:
    """Evaluate a GraphQL endpoint for abuse vectors.

    Args:
        endpoint: The URL of the GraphQL endpoint.
        scoring: Per-validator ``ScoringConfig``.
        graphql_request: Callable performing the HTTP request. Should
            accept ``(endpoint, query_body)`` and return a response dict.
        introspection_query: Query used to test introspection.
        depth_query: Query used to test query depth limits.
        batch_query: Query used to test batching/aliasing.
        max_acceptable_depth: Depth above which the response is considered
            a DoS risk.
        in_scope: Whether the target endpoint is in scope.

    Returns:
        Dict with status/confidence/signals/evidence/bonuses.
    """
    if graphql_request is None:
        return {
            "status": ValidationStatus.INCONCLUSIVE.value,
            "confidence": 0.0,
            "signals": [],
            "evidence": {"reason": "no_graphql_request_callable"},
            "bonuses": [],
        }

    signals: list[str] = []
    bonuses: list[float] = []
    notes: list[str] = []
    responses: dict[str, Any] = {}

    if in_scope:
        intro_response = graphql_request(endpoint, introspection_query)
        responses["introspection"] = intro_response
        if _looks_like_introspection_response(str(intro_response.get("body", ""))):
            signals.append("introspection_exposed")
            bonuses.append(0.20)
            notes.append("GraphQL introspection query succeeded against the endpoint.")

        batch_response = graphql_request(endpoint, batch_query)
        responses["batch"] = batch_response
        if _looks_like_batch_response(str(batch_response.get("body", ""))):
            signals.append("batch_amplification")
            bonuses.append(0.15)
            notes.append("GraphQL batching of identical operations succeeded.")

        depth_response = graphql_request(endpoint, depth_query)
        responses["depth"] = depth_response
        depth_value = _count_nested_braces(depth_query)
        depth_status = int(depth_response.get("status_code", 0) or 0)
        depth_body = str(depth_response.get("body", "") or "")
        depth_rejected = (
            "depth" in depth_body.lower()
            or "complexity" in depth_body.lower()
            or "too deep" in depth_body.lower()
            or depth_status in (400, 413, 422, 500)
            and ("depth" in depth_body.lower() or "complexity" in depth_body.lower())
        )
        if depth_value > max_acceptable_depth and not depth_rejected:
            signals.append("deeply_nested_accepted")
            bonuses.append(0.18)
            notes.append(
                f"GraphQL query depth {depth_value} accepted (limit >{max_acceptable_depth})."
            )

    if signals and in_scope:
        if "introspection_exposed" in signals or "deeply_nested_accepted" in signals:
            status = ValidationStatus.CONFIRMED.value
        else:
            status = ValidationStatus.HEURISTIC.value
    elif signals:
        status = ValidationStatus.HEURISTIC.value
    else:
        status = ValidationStatus.INCONCLUSIVE.value

    confidence = bounded_confidence(
        base=scoring.base,
        cap=scoring.cap,
        bonuses=bonuses,
    )
    evidence = {
        "endpoint": endpoint,
        "introspection_query_depth": _count_nested_braces(introspection_query),
        "batch_query_count": batch_query.count("__typename"),
        "depth_query_depth": _count_nested_braces(depth_query),
        "signals": signals,
        "notes": notes,
        "responses": {
            key: {
                "status_code": value.get("status_code"),
                "body_excerpt": str(value.get("body", ""))[:200],
            }
            for key, value in responses.items()
        },
    }
    return {
        "status": status,
        "confidence": confidence,
        "signals": signals,
        "evidence": evidence,
        "bonuses": bonuses,
    }


def validate_graphql_endpoint(
    *,
    endpoint: str,
    scoring: ScoringConfig,
    graphql_request: Callable[[str, str], dict[str, Any]] | None = None,
    in_scope: bool = True,
) -> dict[str, Any]:
    """Validate a GraphQL endpoint and return a result dict."""
    evaluation = evaluate_graphql(
        endpoint=endpoint,
        scoring=scoring,
        graphql_request=graphql_request,
        in_scope=in_scope,
    )
    item = {
        "url": endpoint,
        "status": evaluation["status"],
        "confidence": evaluation["confidence"],
        "in_scope": in_scope,
        "scope_reason": "scope_evaluated"
        if in_scope
        else "scope_unavailable_or_out_of_scope",
        "evidence": evaluation["evidence"],
    }
    return to_validation_result(
        item, validator="graphql_abuse", category="graphql_abuse"
    ).__dict__


def validate(target: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
    """R1 facade entry point matching the ``Validator`` Protocol.

    Active probing is performed by the engine ``GraphqlValidator``. The
    facade returns a passive result based on heuristic
    ``looks_like_graphql_endpoint`` if no introspection data is present
    in ``context``.
    """
    from src.execution.validators.config.scoring_config import (
        DEFAULT_SCORING_CONFIG,
    )

    endpoint = str(target.get("url", ""))
    graphql_request = context.get("graphql_request")
    if not callable(graphql_request):
        return to_validation_result(
            {
                "url": endpoint,
                "status": ValidationStatus.INCONCLUSIVE.value,
                "confidence": 0.0,
                "in_scope": bool(context.get("in_scope", True)),
                "scope_reason": "no_graphql_request_callable",
            },
            validator="graphql_abuse",
            category="graphql_abuse",
        ).__dict__
    return validate_graphql_endpoint(
        endpoint=endpoint,
        scoring=DEFAULT_SCORING_CONFIG["graphql_abuse"],
        graphql_request=graphql_request,
        in_scope=bool(context.get("in_scope", True)),
    )


def looks_like_graphql_endpoint(content_type: str, body: str) -> bool:
    """Heuristic to detect whether a URL likely serves a GraphQL endpoint."""
    if not content_type or not body:
        return False
    lowered_ct = content_type.lower()
    if "graphql" in lowered_ct:
        return True
    if "application/json" not in lowered_ct:
        return False
    lowered = body[:512].lower()
    return any(
        marker in lowered
        for marker in (
            "\"__schema\"",
            "\"querytype\"",
            "\"mutationtype\"",
            "graphql",
        )
    ) or bool(re.search(r'"query"\s*:', lowered))
