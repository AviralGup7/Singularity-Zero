"""GraphQL active testing for schema enumeration, batch abuse, and mutation probing.

Sends safe GraphQL queries to detected /graphql endpoints to:
- Enumerate schema via introspection queries
- Detect batch query abuse potential
- Test mutation surfaces
- Identify field-level authorization gaps
"""

import json
import re
from typing import Any

from src.analysis.helpers import (
    classify_endpoint,
    endpoint_base_key,
    endpoint_signature,
    is_noise_url,
)
from src.analysis.passive.runtime import ResponseCache

# Safe GraphQL introspection query
GRAPHQL_INTROSPECTION_QUERY = """
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

# Safe GraphQL batch query test
GRAPHQL_BATCH_QUERY = """
[
  {"query": "{ __typename }"},
  {"query": "{ __schema { queryType { name } } }"},
  {"query": "{ __type(name: \"Query\") { name } }"}
]
"""

# Safe GraphQL mutation test (read-only introspection-style mutation)
GRAPHQL_MUTATION_TEST = """
mutation {
  __typename
}
"""

# GraphQL depth limit test (nested query to detect missing depth limits)
GRAPHQL_DEPTH_TEST = """
{
  __typename
  _depth1: __typename
  _depth2: __typename
  _depth3: __typename
  _depth4: __typename
  _depth5: __typename
}
"""

# GraphQL alias abuse test (multiple aliases to detect rate limit bypass)
GRAPHQL_ALIAS_ABUSE = """
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
"""

# GraphQL persisted query bypass test
GRAPHQL_PERSISTED_QUERY_TEST = """
{
  __schema {
    queryType { name }
  }
}
"""

# GraphQL error patterns indicating verbose errors
GRAPHQL_VERBOSE_ERROR_PATTERNS = [
    "cannot query field",
    "unknown type",
    "expected type",
    "syntax error",
    "unexpected name",
    "parse error",
    "validation error",
    "introspection",
    r"field.*not found",
    r"argument.*required",
    r"variable.*not defined",
]

_GRAPHQL_VERBOSE_ERROR_COMPILED = [re.compile(p, re.IGNORECASE) for p in GRAPHQL_VERBOSE_ERROR_PATTERNS]


def _parse_graphql_response(body: str) -> dict[str, Any] | None:
    """Parse a GraphQL JSON response safely.

    Args:
        body: Response body text.

    Returns:
        Parsed JSON dict or None.
    """
    try:
        result: Any = json.loads(body)
        return result if isinstance(result, dict) else None
    except (json.JSONDecodeError, ValueError):
        return None


def _check_graphql_errors(body: str) -> list[str]:
    """Check response body for GraphQL error patterns.

    Args:
        body: Response body text.

    Returns:
        List of error pattern signals found.
    """
    signals = []
    body_lower = body.lower()

    for compiled_re in _GRAPHQL_VERBOSE_ERROR_COMPILED:
        if compiled_re.search(body_lower):
            pattern_str = compiled_re.pattern
            signals.append(f"graphql_error:{pattern_str.split()[0]}")

    # Check for stack traces in GraphQL errors
    if any(kw in body_lower for kw in ("stack trace", "traceback", "at line", "column")):
        signals.append("graphql_stack_trace")

    # Check for internal path leakage
    if any(kw in body_lower for kw in ("resolver", "schema.", "type.", "field.")):
        signals.append("graphql_internal_leak")

    return signals


def graphql_active_probe(
    priority_urls: list[dict[str, Any]], response_cache: ResponseCache, limit: int = 8
) -> list[dict[str, Any]]:
    """Send safe GraphQL probes to detected /graphql endpoints.

    Tests:
    1. Introspection query execution
    2. Batch query abuse potential
    3. Mutation surface detection

    Args:
        priority_urls: List of URL dicts with endpoint metadata.
        response_cache: Response cache for making requests.
        limit: Maximum number of findings to return.

    Returns:
        List of GraphQL probe findings.
    """
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()

    for url_entry in priority_urls:
        if len(findings) >= limit:
            break

        url = str(url_entry.get("url", "") if isinstance(url_entry, dict) else url_entry).strip()
        if not url or is_noise_url(url):
            continue

        # Only test GraphQL endpoints
        if "/graphql" not in url.lower():
            continue

        endpoint_key = endpoint_signature(url)
        if endpoint_key in seen:
            continue

        signals: list[str] = []
        introspection_result = None
        batch_result = None
        mutation_result = None

        # Test 1: Introspection query
        introspection_response = response_cache.request(
            url,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Cache-Control": "no-cache",
                "X-GraphQL-Probe": "introspection",
            },
            body=json.dumps({"query": GRAPHQL_INTROSPECTION_QUERY}),
        )

        if introspection_response:
            body = str(introspection_response.get("body_text") or "")
            status = int(introspection_response.get("status_code") or 0)
            parsed = _parse_graphql_response(body)

            if parsed:
                if "data" in parsed and "__schema" in parsed.get("data", {}):
                    signals.append("introspection_enabled")
                    introspection_result = {
                        "status_code": status,
                        "schema_exposed": True,
                        "type_count": len(parsed["data"]["__schema"].get("types", [])),
                    }
                elif "errors" in parsed:
                    error_signals = _check_graphql_errors(body)
                    signals.extend(error_signals)
                    introspection_result = {
                        "status_code": status,
                        "schema_exposed": False,
                        "errors": len(parsed["errors"]),
                    }
            elif body:
                error_signals = _check_graphql_errors(body)
                signals.extend(error_signals)

        # Test 2: Batch query abuse
        batch_response = response_cache.request(
            url,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Cache-Control": "no-cache",
                "X-GraphQL-Probe": "batch",
            },
            body=GRAPHQL_BATCH_QUERY,
        )

        if batch_response:
            body = str(batch_response.get("body_text") or "")
            status = int(batch_response.get("status_code") or 0)
            parsed = _parse_graphql_response(body)

            if parsed and isinstance(parsed, list):
                signals.append("batch_query_accepted")
                batch_result = {
                    "status_code": status,
                    "batch_size": len(parsed),
                    "all_succeeded": all("data" in item for item in parsed),
                }
            elif parsed and "errors" in parsed:
                signals.append("batch_query_rejected")

        # Test 3: Mutation surface
        mutation_response = response_cache.request(
            url,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Cache-Control": "no-cache",
                "X-GraphQL-Probe": "mutation",
            },
            body=json.dumps({"query": GRAPHQL_MUTATION_TEST}),
        )

        if mutation_response:
            body = str(mutation_response.get("body_text") or "")
            status = int(mutation_response.get("status_code") or 0)
            parsed = _parse_graphql_response(body)

            if parsed:
                if "data" in parsed:
                    signals.append("mutation_endpoint")
                    mutation_result = {"status_code": status, "mutation_accepted": True}
                elif "errors" in parsed:
                    error_signals = _check_graphql_errors(body)
                    signals.extend(error_signals)
                    mutation_result = {"status_code": status, "mutation_rejected": True}

        # Test 4: Depth limit detection (nested query abuse)
        depth_response = response_cache.request(
            url,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Cache-Control": "no-cache",
                "X-GraphQL-Probe": "depth",
            },
            body=json.dumps({"query": GRAPHQL_DEPTH_TEST}),
        )

        if depth_response:
            body = str(depth_response.get("body_text") or "")
            status = int(depth_response.get("status_code") or 0)
            parsed = _parse_graphql_response(body)

            if parsed and "data" in parsed:
                signals.append("depth_limit_not_enforced")
            elif parsed and "errors" in parsed:
                error_text = str(parsed.get("errors", [])).lower()
                if "depth" in error_text or "too deep" in error_text or "nested" in error_text:
                    signals.append("depth_limit_enforced")

        # Test 5: Alias abuse (rate limit bypass via multiple aliases)
        alias_response = response_cache.request(
            url,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Cache-Control": "no-cache",
                "X-GraphQL-Probe": "alias_abuse",
            },
            body=json.dumps({"query": GRAPHQL_ALIAS_ABUSE}),
        )

        if alias_response:
            body = str(alias_response.get("body_text") or "")
            status = int(alias_response.get("status_code") or 0)
            parsed = _parse_graphql_response(body)

            if parsed and "data" in parsed:
                signals.append("alias_abuse_accepted")
            elif parsed and "errors" in parsed:
                error_text = str(parsed.get("errors", [])).lower()
                if "alias" in error_text or "too many" in error_text:
                    signals.append("alias_abuse_rejected")

        # Test 6: Persisted query bypass
        persisted_response = response_cache.request(
            url,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Cache-Control": "no-cache",
                "X-GraphQL-Probe": "persisted_query",
            },
            body=json.dumps(
                {
                    "query": GRAPHQL_PERSISTED_QUERY_TEST,
                    "extensions": {"persistedQuery": {"version": 1, "sha256Hash": "test"}},
                }
            ),
        )

        if persisted_response:
            body = str(persisted_response.get("body_text") or "")
            status = int(persisted_response.get("status_code") or 0)
            parsed = _parse_graphql_response(body)

            if parsed and "data" in parsed:
                signals.append("persisted_query_bypass")
            elif parsed and "errors" in parsed:
                error_text = str(parsed.get("errors", [])).lower()
                if "persisted" in error_text or "not found" in error_text:
                    signals.append("persisted_query_enforced")

        if not signals:
            continue

        seen.add(endpoint_key)

        # Calculate risk score with new test results
        risk_score = 0
        if "introspection_enabled" in signals:
            risk_score += 8
        if "batch_query_accepted" in signals:
            risk_score += 5
        if "mutation_endpoint" in signals:
            risk_score += 4
        if any("graphql_error" in s for s in signals):
            risk_score += 3
        if "graphql_stack_trace" in signals:
            risk_score += 6
        if "depth_limit_not_enforced" in signals:
            risk_score += 4
        if "alias_abuse_accepted" in signals:
            risk_score += 3
        if "persisted_query_bypass" in signals:
            risk_score += 5

        severity = "high" if risk_score >= 8 else "medium" if risk_score >= 4 else "low"

        findings.append(
            {
                "url": url,
                "endpoint_key": endpoint_key,
                "endpoint_base_key": endpoint_base_key(url),
                "endpoint_type": classify_endpoint(url),
                "graphql_signals": sorted(signals),
                "risk_score": risk_score,
                "severity": severity,
                "introspection_result": introspection_result,
                "batch_result": batch_result,
                "mutation_result": mutation_result,
            }
        )

    findings.sort(key=lambda item: (-item.get("risk_score", 0), item.get("url", "")))
    return findings
