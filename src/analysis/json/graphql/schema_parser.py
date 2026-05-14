"""GraphQL schema parsing utilities for introspection analysis."""

import json
import logging
from typing import Any
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

GRAPHQL_ENDPOINT_PATHS = [
    "/graphql",
    "/graphiql",
    "/api/graphql",
    "/v1/graphql",
    "/v2/graphql",
    "/v3/graphql",
    "/graphql/console",
    "/playground",
    "/altair",
    "/api/v1/graphql",
    "/api/v2/graphql",
    "/query",
    "/api/query",
    "/gql",
    "/api/gql",
]


def parse_json_body(body: str) -> dict[str, Any] | list[Any] | None:
    """Safely parse a JSON body."""
    try:
        return json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return None


def has_graphql_indicators(body: str, status_code: int) -> bool:
    """Check if a response looks like a GraphQL response."""
    if not body:
        return False
    indicators = [
        '"data"',
        '"errors"',
        '"__typename"',
        '"__schema"',
        '"message"',
        '"locations"',
        '"path"',
    ]
    body_lower = body.lower().strip()
    if body_lower.startswith(("{", "[")):
        parsed = parse_json_body(body)
        if isinstance(parsed, dict):
            if any(k in parsed for k in ("data", "errors")):
                return True
            if any(ind in body_lower for ind in indicators):
                return True
    return False


def make_graphql_request(
    endpoint: str, session, query: str, operation_name: str | None = None
) -> dict[str, Any]:
    """Send a GraphQL POST request and return parsed response info."""
    body = {"query": query}
    if operation_name:
        body["operationName"] = operation_name
    try:
        resp = session.post(
            endpoint,
            json=body,
            headers={"Content-Type": "application/json"},
            timeout=15,
        )
        return {
            "status_code": resp.status_code,
            "body": resp.text[:10000],
            "headers": dict(resp.headers),
            "success": resp.status_code in (200, 400, 401, 403, 500),
        }
    except Exception as exc:
        logger.debug("GraphQL request failed for %s: %s", endpoint, exc)
        return {"status_code": 0, "body": "", "headers": {}, "success": False, "error": str(exc)}


def detect_graphql_endpoints(urls: list[str], session) -> list[dict[str, Any]]:
    """Detect GraphQL endpoints by probing common paths."""
    detected: list[dict[str, Any]] = []
    seen_hosts: set[str] = set()

    for base_url in urls:
        base_url = base_url.rstrip("/")
        if not base_url.startswith(("http://", "https://")):
            continue

        parsed = urlparse(base_url)
        host_key = f"{parsed.scheme}://{parsed.netloc}"
        if host_key in seen_hosts:
            continue

        for path in GRAPHQL_ENDPOINT_PATHS:
            candidate = f"{host_key}{path}"
            try:
                resp = session.post(
                    candidate,
                    json={"query": "{ __typename }"},
                    headers={"Content-Type": "application/json"},
                    timeout=10,
                )
                if has_graphql_indicators(resp.text, resp.status_code):
                    detection = {
                        "url": candidate,
                        "status_code": resp.status_code,
                        "detection_method": "typename_probe",
                        "content_type": resp.headers.get("Content-Type", ""),
                    }
                    detected.append(detection)
                    seen_hosts.add(host_key)
                    break
            except Exception:
                continue

        if host_key not in seen_hosts:
            for path in GRAPHQL_ENDPOINT_PATHS:
                candidate = f"{host_key}{path}"
                try:
                    resp = session.get(candidate, timeout=10)
                    if resp.status_code in (200, 400, 405):
                        body_lower = resp.text.lower()
                        if "graphql" in body_lower or "graphiql" in body_lower:
                            detection = {
                                "url": candidate,
                                "status_code": resp.status_code,
                                "detection_method": "body_keyword",
                                "content_type": resp.headers.get("Content-Type", ""),
                            }
                            detected.append(detection)
                            seen_hosts.add(host_key)
                            break
                except Exception:
                    continue

    return detected


def parse_schema_from_introspection(introspection_result: dict[str, Any]) -> dict[str, Any]:
    """Extract structured schema info from raw introspection data."""
    schema = introspection_result.get("schema")
    if not schema:
        return {}

    parsed = {
        "query_type": introspection_result.get("query_type"),
        "mutation_type": introspection_result.get("mutation_type"),
        "subscription_type": introspection_result.get("subscription_type"),
        "type_count": introspection_result.get("type_count", 0),
        "mutations": introspection_result.get("mutations", []),
        "types_by_kind": {},
    }

    for t in schema.get("types", []):
        kind = t.get("kind", "UNKNOWN")
        if kind not in parsed["types_by_kind"]:
            parsed["types_by_kind"][kind] = []
        parsed["types_by_kind"][kind].append(
            {
                "name": t.get("name"),
                "description": t.get("description"),
            }
        )

    return parsed
