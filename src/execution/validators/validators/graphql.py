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

# Authorization bypass queries: tests whether batching or alias tricks
# bypass per-field authorization.
AUTH_BYPASS_QUERIES: list[dict[str, str]] = [
    {
        "label": "batch_auth_bypass",
        "query": "[{query Me{me{id,email,role}}},{query Users{users{id,email,role}}}]",
    },
    {
        "label": "alias_field_suggestion",
        "query": "{a1:__typename a2:__typename a3:__typename a4:__typename a5:__typename}",
    },
]

# Fragment DoS: deeply recursive fragment references that can cause infinite loops.
FRAGMENT_DOS_QUERY = "fragment Frag on __Type { fields { type { ...Frag } } }\n{ ...Frag }"

# Persisted query hijacking: test for common persisted query IDs.
PERSISTED_QUERY_IDS = [
    "persisted-query-1",
    "query-001",
    "sha256:0000000000000000000000000000000000000000000000000000000000000000",
    "1",
    "0",
    "00000000-0000-4000-8000-000000000000",
    "ecosse",
    "persistedQuery",
    "sha256hash",
    "1a2b3c4d5e6f",
]

# Fragment-based DoS probe - circular fragment reference
FRAGMENT_CIRCULAR_QUERY = (
    "fragment A on Query { ...B } "
    "fragment B on Query { ...A } "
    "{ ...A }"
)

# Directive abuse probe - @include/@skip with always-true/always-false
DIRECTIVE_ABUSE_QUERY = (
    "{__typename @include(if:true) @skip(if:false){__typename}}"
)

# Auth bypass via batching - queries that may bypass per-field authorization
AUTH_BYPASS_BATCH_QUERY = (
    "[{__typename,secretField},{__typename,secretField}]"
)


# Subscription abuse probe - tests if subscriptions can be created
# without authentication
SUBSCRIPTION_ABUSE_QUERY = (
    "subscription { __typename }"
)

# Field suggestions probe - tests if the server leaks field names
# in error messages (suggestions leak sensitive schema info)
FIELD_SUGGESTIONS_QUERY = (
    "{ __type }"
)

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


def _looks_like_fragment_circular(body: str) -> bool:
    """Check if body suggests a circular fragment query succeeded."""
    if not body:
        return False
    try:
        parsed = json.loads(body)
        if isinstance(parsed, list):
            return any(isinstance(item, dict) and bool(item.get("data", {})) for item in parsed)
        return isinstance(parsed, dict) and bool(parsed.get("data", {}))
    except (ValueError, TypeError):
        return False


def _looks_like_directive_abuse(body: str) -> bool:
    """Check if body suggests a @include/@skip directive abuse succeeded."""
    if not body:
        return False
    return "__typename" in body


def _looks_like_persisted_query(body: str) -> bool:
    """Check if body suggests a persisted query hijacking."""
    if not body:
        return False
    try:
        parsed = json.loads(body)
        if isinstance(parsed, list):
            return any(isinstance(item, dict) and bool(item.get("data", {})) for item in parsed)
        return isinstance(parsed, dict) and bool(parsed.get("data", {}))
    except (ValueError, TypeError):
        return False


def _looks_like_subscription_response(body: str) -> bool:
    """Check if body suggests a subscription request was accepted."""
    if not body:
        return False
    try:
        parsed = json.loads(body)
        if isinstance(parsed, list):
            return any(isinstance(item, dict) and bool(item.get("data", {})) for item in parsed) and "__typename" in body
        return isinstance(parsed, dict) and bool(parsed.get("data", {})) and "__typename" in body
    except (ValueError, TypeError):
        return False


def _looks_like_field_suggestions(body: str) -> bool:
    """Check if body suggests field suggestions leak."""
    if not body:
        return False
    lowered = body.lower()
    return bool(re.search(r'did you mean', lowered, re.IGNORECASE)) or (
        "cannot query field" in lowered
    )


def evaluate_graphql(
    *,
    endpoint: str,
    scoring: ScoringConfig,
    graphql_request: Callable[[str, str], dict[str, Any]] | None = None,
    introspection_query: str = INTROSPECTION_QUERY,
    depth_query: str = _DEPTH_PROBE_QUERY,
    batch_query: str = BATCH_QUERY,
    fragment_query: str = FRAGMENT_CIRCULAR_QUERY,
    directive_query: str = DIRECTIVE_ABUSE_QUERY,
    auth_bypass_query: str = AUTH_BYPASS_BATCH_QUERY,
    persisted_query_ids: list[str] | None = None,
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
        fragment_query: Query used to test circular fragment DoS.
        directive_query: Query used to test @include/@skip directive abuse.
        auth_bypass_query: Query used to test auth bypass via batching.
        persisted_query_ids: List of persisted query IDs to try.
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
    persisted_query_ids = persisted_query_ids or PERSISTED_QUERY_IDS

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
            or (depth_status in (400, 413, 422, 500) and ("depth" in depth_body.lower() or "complexity" in depth_body.lower()))
        )
        if depth_value > max_acceptable_depth and not depth_rejected:
            signals.append("deeply_nested_accepted")
            bonuses.append(0.18)
            notes.append(
                f"GraphQL query depth {depth_value} accepted (limit >{max_acceptable_depth})."
            )

        # Fragment-based DoS (circular fragment)
        fragment_response = graphql_request(endpoint, fragment_query)
        responses["fragment_circular"] = fragment_response
        if _looks_like_fragment_circular(str(fragment_response.get("body", ""))):
            signals.append("fragment_circular_accepted")
            bonuses.append(0.15)
            notes.append("Circular fragment reference query accepted - DoS risk.")

        # Directive abuse (@include/@skip)
        directive_response = graphql_request(endpoint, directive_query)
        responses["directive_abuse"] = directive_response
        if _looks_like_directive_abuse(str(directive_response.get("body", ""))):
            signals.append("directive_abuse_accepted")
            bonuses.append(0.12)
            notes.append("@include/@skip directive abuse without proper validation.")

        # Auth bypass via batching (batched queries accessing potentially
        # unauthorized fields)
        auth_bypass_response = graphql_request(endpoint, auth_bypass_query)
        responses["auth_bypass"] = auth_bypass_response
        if _looks_like_batch_response(str(auth_bypass_response.get("body", ""))):
            signals.append("auth_bypass_batch_accepted")
            bonuses.append(0.18)
            notes.append("Auth bypass via batched query succeeded - potential privilege escalation.")

        # Persisted query hijacking
        for pq_id in persisted_query_ids[:3]:
            persisted_body = json.dumps({
                "id": pq_id,
                "variables": "{}",
            })
            pq_response = graphql_request(endpoint, persisted_body)
            responses[f"persisted_query_{pq_id}"] = pq_response
            if _looks_like_persisted_query(str(pq_response.get("body", ""))):
                signals.append("persisted_query_hijacking")
                bonuses.append(0.15)
                notes.append(f"Persisted query ID '{pq_id}' resolved - potential hijacking.")

        # Subscription abuse - tests if subscriptions can be created
        # without authentication
        subscription_response = graphql_request(endpoint, SUBSCRIPTION_ABUSE_QUERY)
        responses["subscription_abuse"] = subscription_response
        if _looks_like_subscription_response(str(subscription_response.get("body", ""))):
            signals.append("subscription_abuse")
            bonuses.append(0.12)
            notes.append("Subscription accepted - potential unauthenticated subscription access.")

        # Field suggestions leak - tests if error messages suggest field names
        suggestion_response = graphql_request(endpoint, FIELD_SUGGESTIONS_QUERY)
        responses["field_suggestions"] = suggestion_response
        if _looks_like_field_suggestions(str(suggestion_response.get("body", ""))):
            signals.append("field_suggestions_leak")
            bonuses.append(0.10)
            notes.append("Error messages leak field name suggestions - information disclosure.")

    if signals and in_scope:
        if "introspection_exposed" in signals or "deeply_nested_accepted" in signals or "fragment_circular_accepted" in signals:
            status = ValidationStatus.CONFIRMED.value
        elif "persisted_query_hijacking" in signals or "directive_abuse_accepted" in signals:
            status = ValidationStatus.HEURISTIC.value
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
        "fragment_query_depth": _count_nested_braces(fragment_query),
        "signals": signals,
        "notes": notes,
        "persisted_query_ids_tested": persisted_query_ids[:3],
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
