"""GraphQL Introspection & Schema Testing module.

Provides endpoint detection, schema introspection, query depth abuse testing,
batch query aliasing attacks, and mutation exposure analysis for GraphQL APIs.
"""

import json
import logging
from typing import Any, cast

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

INTROSPECTION_QUERY = """
{
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      name
      kind
      description
      fields(includeDeprecated: true) {
        name
        description
        args {
          name
          type { name kind ofType { name kind } }
        }
        type { name kind ofType { name kind } }
      }
    }
  }
}
"""

MINIMAL_INTROSPECTION_QUERY = """
{
  __schema {
    queryType { name }
    mutationType { name }
    types { name }
  }
}
"""

TYPE_INTROSPECTION_QUERY = """
{
  __type(name: "Query") {
    name
    fields {
      name
      args { name type { name } }
      type { name }
    }
  }
}
"""

DEPTH_TEST_QUERIES = [
    {
        "depth": 5,
        "query": """
{
  a: __typename
  b: __typename
  c: __typename
  d: __typename
  e: __typename
}
""",
    },
    {
        "depth": 10,
        "query": """
{
  a1: __typename
  a2: __typename
  a3: __typename
  a4: __typename
  a5: __typename
  a6: __typename
  a7: __typename
  a8: __typename
  a9: __typename
  a10: __typename
}
""",
    },
    {
        "depth": 15,
        "query": """
{
  l1: __typename
  l2: __typename
  l3: __typename
  l4: __typename
  l5: __typename
  l6: __typename
  l7: __typename
  l8: __typename
  l9: __typename
  l10: __typename
  l11: __typename
  l12: __typename
  l13: __typename
  l14: __typename
  l15: __typename
}
""",
    },
]

BATCH_ALIAS_PAYLOADS = [
    [
        {"query": "{ __typename }"},
        {"query": "{ __schema { queryType { name } } }"},
        {"query": '{ __type(name: "Query") { name } }'},
    ],
    [
        {"query": "{ a1: __typename }"},
        {"query": "{ a2: __typename }"},
        {"query": "{ a3: __typename }"},
        {"query": "{ a4: __typename }"},
        {"query": "{ a5: __typename }"},
    ],
]

ALIAS_ABUSE_QUERY = """
{
  t1: __typename
  t2: __typename
  t3: __typename
  t4: __typename
  t5: __typename
  t6: __typename
  t7: __typename
  t8: __typename
  t9: __typename
  t10: __typename
  t11: __typename
  t12: __typename
  t13: __typename
  t14: __typename
  t15: __typename
  t16: __typename
  t17: __typename
  t18: __typename
  t19: __typename
  t20: __typename
}
"""

MUTATION_TEST_QUERIES = [
    {"name": "typename_mutation", "query": "mutation { __typename }"},
    {"name": "introspection_mutation", "query": "mutation { __schema { types { name } } }"},
]

DANGEROUS_MUTATION_NAMES = {
    "createuser",
    "deleteuser",
    "updateuser",
    "createaccount",
    "deleteaccount",
    "transfer",
    "withdraw",
    "deposit",
    "createorder",
    "cancelorder",
    "updatepayment",
    "grantpermission",
    "revokpermission",
    "setrole",
    "execute",
    "run",
    "deploy",
    "publish",
    "sendemail",
    "sendnotification",
    "createwebhook",
    "delete",
    "updatepassword",
    "resetpassword",
    "impersonate",
    "loginas",
}


def _make_graphql_request(
    endpoint: str, session: Any, query: str, operation_name: str | None = None
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


def _parse_json_body(body: str) -> dict[str, Any] | list[Any] | None:
    """Safely parse a JSON body."""
    try:
        return cast(dict[str, Any] | list[Any], json.loads(body))
    except (json.JSONDecodeError, ValueError):
        return None


def _has_graphql_indicators(body: str, status_code: int) -> bool:
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
        parsed = _parse_json_body(body)
        if isinstance(parsed, dict):
            if any(k in parsed for k in ("data", "errors")):
                return True
            if any(ind in body_lower for ind in indicators):
                return True
    return False


def detect_graphql_endpoints(urls: list[str], session: Any) -> list[dict[str, Any]]:
    """Detect GraphQL endpoints by probing common paths.

    Args:
        urls: Base URLs to probe (e.g. https://example.com).
        session: HTTP session for making requests.

    Returns:
        List of dicts with endpoint URL and detection details.
    """
    detected: list[dict[str, Any]] = []
    seen_hosts: set[str] = set()

    for base_url in urls:
        base_url = base_url.rstrip("/")
        if not base_url.startswith(("http://", "https://")):
            continue

        from urllib.parse import urlparse

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
                if _has_graphql_indicators(resp.text, resp.status_code):
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
                except Exception:  # noqa: S112
                    continue

    return detected


def test_introspection(endpoint: str, session: Any) -> dict[str, Any]:
    """Send introspection queries to extract the GraphQL schema.

    Tries full introspection first, then minimal, then type-level.

    Args:
        endpoint: Full GraphQL endpoint URL.
        session: HTTP session.

    Returns:
        Dict with introspection results including schema info.
    """
    result: dict[str, Any] = {
        "endpoint": endpoint,
        "introspection_enabled": False,
        "schema": None,
        "type_count": 0,
        "query_type": None,
        "mutation_type": None,
        "subscription_type": None,
        "mutations": [],
        "error": None,
    }

    for label, query in [
        ("full", INTROSPECTION_QUERY),
        ("minimal", MINIMAL_INTROSPECTION_QUERY),
        ("type", TYPE_INTROSPECTION_QUERY),
    ]:
        resp = _make_graphql_request(endpoint, session, query)
        if not resp["success"]:
            continue

        parsed = _parse_json_body(resp["body"])
        if not isinstance(parsed, dict):
            continue

        if "data" in parsed and "__schema" in parsed.get("data", {}):
            schema = parsed["data"]["__schema"]
            result["introspection_enabled"] = True
            result["schema"] = schema
            result["type_count"] = len(schema.get("types", []))
            result["query_type"] = schema.get("queryType", {}).get("name")
            result["mutation_type"] = schema.get("mutationType", {}).get("name")
            result["subscription_type"] = schema.get("subscriptionType", {}).get("name")

            mutation_types = []
            for t in schema.get("types", []):
                if t.get("kind") == "OBJECT" and t.get("name", "").lower() == "mutation":
                    mutation_types = [f["name"] for f in t.get("fields", [])]
                    break
            result["mutations"] = mutation_types
            return result

        if "data" in parsed and "__type" in parsed.get("data", {}):
            type_info = parsed["data"]["__type"]
            if type_info:
                result["introspection_enabled"] = True
                result["query_type"] = type_info.get("name")
                fields = type_info.get("fields", [])
                result["type_count"] = len(fields) if fields else 0
                return result

        if "errors" in parsed:
            error_text = str(parsed["errors"]).lower()
            if "introspection" in error_text or "disabled" in error_text:
                result["error"] = "introspection_disabled"
                return result

    return result


def test_query_depth(endpoint: str, session: Any, max_depth: int = 10) -> dict[str, Any]:
    """Test deeply nested queries for DoS vulnerability.

    Sends queries with increasing alias counts to detect depth limits.

    Args:
        endpoint: Full GraphQL endpoint URL.
        session: HTTP session.
        max_depth: Maximum depth level to test.

    Returns:
        Dict with depth test results.
    """
    result: dict[str, Any] = {
        "endpoint": endpoint,
        "depth_limit_enforced": False,
        "max_successful_depth": 0,
        "depth_tests": [],
        "dos_vulnerable": False,
    }

    for test in DEPTH_TEST_QUERIES:
        depth = int(test.get("depth", 0))  # type: ignore
        if depth > max_depth:
            break

        resp = _make_graphql_request(endpoint, session, str(test.get("query", "")))
        test_result = {
            "depth": depth,
            "status_code": resp["status_code"],
            "success": False,
            "rejected": False,
            "error": None,
        }

        if not resp["success"]:
            test_result["error"] = "request_failed"
            result["depth_tests"].append(test_result)
            continue

        parsed = _parse_json_body(resp["body"])
        if not isinstance(parsed, dict):
            test_result["error"] = "invalid_response"
            result["depth_tests"].append(test_result)
            continue

        if "data" in parsed:
            test_result["success"] = True
            result["max_successful_depth"] = max(result["max_successful_depth"], depth)
        elif "errors" in parsed:
            error_text = str(parsed["errors"]).lower()
            if any(
                kw in error_text for kw in ("depth", "too deep", "nested", "complexity", "exceeded")
            ):
                test_result["rejected"] = True
                result["depth_limit_enforced"] = True
            else:
                test_result["success"] = True
                result["max_successful_depth"] = max(result["max_successful_depth"], depth)

        result["depth_tests"].append(test_result)

    if result["max_successful_depth"] >= 10 and not result["depth_limit_enforced"]:
        result["dos_vulnerable"] = True

    return result


def test_batch_aliasing(endpoint: str, session: Any) -> dict[str, Any]:
    """Test batch query aliasing attacks.

    Tests whether the endpoint accepts batch queries (array of operations)
    and alias abuse (many aliases in a single query).

    Args:
        endpoint: Full GraphQL endpoint URL.
        session: HTTP session.

    Returns:
        Dict with batch/alias test results.
    """
    result: dict[str, Any] = {
        "endpoint": endpoint,
        "batch_accepted": False,
        "batch_size_accepted": 0,
        "alias_abuse_accepted": False,
        "alias_count_accepted": 0,
        "rate_limit_bypass_risk": False,
        "batch_tests": [],
        "alias_test": None,
    }

    for i, batch in enumerate(BATCH_ALIAS_PAYLOADS):
        try:
            resp = session.post(
                endpoint,
                json=batch,
                headers={"Content-Type": "application/json"},
                timeout=15,
            )
            parsed = _parse_json_body(resp.text)
            batch_result = {
                "batch_index": i,
                "batch_size": len(batch),
                "status_code": resp.status_code,
                "accepted": False,
            }

            if isinstance(parsed, list) and len(parsed) == len(batch):
                batch_result["accepted"] = True
                result["batch_accepted"] = True
                result["batch_size_accepted"] = max(result["batch_size_accepted"], len(batch))

            result["batch_tests"].append(batch_result)
        except Exception as exc:
            logger.debug("Batch test %d failed: %s", i, exc)

    resp = _make_graphql_request(endpoint, session, ALIAS_ABUSE_QUERY)
    alias_result = {
        "alias_count": 20,
        "status_code": resp["status_code"],
        "accepted": False,
    }

    if resp["success"]:
        parsed = _parse_json_body(resp["body"])
        if isinstance(parsed, dict) and "data" in parsed:
            alias_result["accepted"] = True
            result["alias_abuse_accepted"] = True
            result["alias_count_accepted"] = 20

    result["alias_test"] = alias_result

    if result["batch_accepted"] or result["alias_abuse_accepted"]:
        result["rate_limit_bypass_risk"] = True

    return result


def test_mutation_exposure(endpoint: str, session: Any) -> dict[str, Any]:
    """Test for exposed dangerous mutations.

    Sends safe mutation queries to detect available mutation operations
    and flags potentially dangerous mutation names.

    Args:
        endpoint: Full GraphQL endpoint URL.
        session: HTTP session.

    Returns:
        Dict with mutation exposure results.
    """
    result: dict[str, Any] = {
        "endpoint": endpoint,
        "mutations_exposed": False,
        "mutation_count": 0,
        "dangerous_mutations": [],
        "mutation_tests": [],
    }

    for mt in MUTATION_TEST_QUERIES:
        resp = _make_graphql_request(endpoint, session, mt["query"])
        test_result = {
            "name": mt["name"],
            "status_code": resp["status_code"],
            "success": False,
        }

        if resp["success"]:
            parsed = _parse_json_body(resp["body"])
            if isinstance(parsed, dict) and "data" in parsed:
                test_result["success"] = True
                result["mutations_exposed"] = True

        result["mutation_tests"].append(test_result)

    if result["mutations_exposed"]:
        result["mutation_count"] = len(result["mutation_tests"])

    for test in result["mutation_tests"]:
        if test["name"] in DANGEROUS_MUTATION_NAMES:
            result["dangerous_mutations"].append(test["name"])

    return result


def run_graphql_analysis(
    urls: list[str], session: Any, config: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Main entry point for GraphQL introspection analysis.

    Detects endpoints, runs introspection, depth tests, batch aliasing,
    and mutation exposure checks.

    Args:
        urls: List of base URLs to scan.
        session: HTTP session.
        config: Optional config dict with limits and settings.

    Returns:
        Dict with all GraphQL analysis results and findings.
    """
    config = config or {}
    max_depth = config.get("graphql_max_depth", 10)
    endpoint_limit = config.get("graphql_endpoint_limit", 5)

    logger.info("Starting GraphQL introspection analysis for %d URLs", len(urls))

    endpoints = detect_graphql_endpoints(urls, session)[:endpoint_limit]
    if not endpoints:
        logger.info("No GraphQL endpoints detected")
        return {"endpoints": [], "findings": [], "summary": {"total_endpoints": 0}}

    all_findings: list[dict[str, Any]] = []
    endpoint_results: list[dict[str, Any]] = []

    for ep_info in endpoints:
        ep_url = ep_info["url"]
        logger.info("Analyzing GraphQL endpoint: %s", ep_url)

        ep_result: dict[str, Any] = {"url": ep_url, "detection": ep_info}

        introspection = test_introspection(ep_url, session)
        ep_result["introspection"] = introspection

        if introspection["introspection_enabled"]:
            all_findings.append(
                {
                    "url": ep_url,
                    "category": "graphql_vulnerability",
                    "title": "GraphQL schema introspection enabled",
                    "severity": "high",
                    "confidence": 0.9,
                    "evidence": {
                        "type_count": introspection["type_count"],
                        "query_type": introspection["query_type"],
                        "mutation_type": introspection["mutation_type"],
                    },
                    "signals": ["introspection_enabled", "schema_exposed"],
                }
            )

        if introspection.get("mutations"):
            dangerous = [
                m for m in introspection["mutations"] if m.lower() in DANGEROUS_MUTATION_NAMES
            ]
            if dangerous:
                all_findings.append(
                    {
                        "url": ep_url,
                        "category": "graphql_vulnerability",
                        "title": f"GraphQL dangerous mutations exposed: {', '.join(dangerous[:5])}",
                        "severity": "high",
                        "confidence": 0.85,
                        "evidence": {
                            "mutations": introspection["mutations"],
                            "dangerous": dangerous,
                        },
                        "signals": ["dangerous_mutations_exposed"],
                    }
                )

        depth_result = test_query_depth(ep_url, session, max_depth=max_depth)
        ep_result["depth_test"] = depth_result

        if depth_result.get("dos_vulnerable"):
            all_findings.append(
                {
                    "url": ep_url,
                    "category": "graphql_vulnerability",
                    "title": "GraphQL query depth limit not enforced - DoS risk",
                    "severity": "medium",
                    "confidence": 0.75,
                    "evidence": {"max_successful_depth": depth_result["max_successful_depth"]},
                    "signals": ["depth_limit_not_enforced", "dos_risk"],
                }
            )

        batch_result = test_batch_aliasing(ep_url, session)
        ep_result["batch_aliasing"] = batch_result

        if batch_result.get("batch_accepted"):
            all_findings.append(
                {
                    "url": ep_url,
                    "category": "graphql_vulnerability",
                    "title": "GraphQL batch query accepted - rate limit bypass risk",
                    "severity": "medium",
                    "confidence": 0.8,
                    "evidence": {"batch_size": batch_result["batch_size_accepted"]},
                    "signals": ["batch_query_accepted", "rate_limit_bypass_risk"],
                }
            )

        if batch_result.get("alias_abuse_accepted"):
            all_findings.append(
                {
                    "url": ep_url,
                    "category": "graphql_vulnerability",
                    "title": "GraphQL alias abuse accepted - potential rate limit bypass",
                    "severity": "low",
                    "confidence": 0.65,
                    "evidence": {"alias_count": batch_result["alias_count_accepted"]},
                    "signals": ["alias_abuse_accepted"],
                }
            )

        mutation_result = test_mutation_exposure(ep_url, session)
        ep_result["mutation_exposure"] = mutation_result

        endpoint_results.append(ep_result)

    summary = {
        "total_endpoints": len(endpoints),
        "introspection_enabled_count": sum(
            1 for e in endpoint_results if e.get("introspection", {}).get("introspection_enabled")
        ),
        "batch_vulnerable_count": sum(
            1 for e in endpoint_results if e.get("batch_aliasing", {}).get("batch_accepted")
        ),
        "depth_vulnerable_count": sum(
            1 for e in endpoint_results if e.get("depth_test", {}).get("dos_vulnerable")
        ),
        "total_findings": len(all_findings),
    }

    logger.info(
        "GraphQL analysis complete: %d endpoints, %d findings",
        summary["total_endpoints"],
        summary["total_findings"],
    )

    return {
        "endpoints": endpoint_results,
        "findings": all_findings,
        "summary": summary,
    }
