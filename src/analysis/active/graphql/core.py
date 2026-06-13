"""GraphQL active testing for schema enumeration, batch abuse, and mutation probing.

Sends safe GraphQL queries to detected /graphql endpoints to:
- Enumerate schema via introspection queries
- Detect batch query abuse potential
- Test mutation surfaces
- Identify field-level authorization gaps
- Probe directive-based access-control bypass (@skip / @include / custom)
- Detect GET-based query acceptance (CSRF amplification surface)
- Chain argument-mutation IDOR (e.g., swap userId / id / accountId in mutations)
"""

import json
import re
from typing import Any
from urllib.parse import quote

from src.analysis.helpers import (
    classify_endpoint,
    endpoint_base_key,
    endpoint_signature,
    is_noise_url,
)

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

# GraphQL directive-based access-control bypass.
# Targets common access-control directives (@skip, @include, @auth, @requireAuth,
# @hasRole, @allowed, @checkPermission). When a server evaluates directives
# in a way that allows a client-controlled variable to "skip" an authorization
# check, these queries expose it. We vary the boolean input across requests.
GRAPHQL_DIRECTIVE_BYPASS_QUERIES = {
    "@skip": """
query BypassSkip($cond: Boolean!) {
  me @skip(if: $cond) {
    id
    email
  }
}
""",
    "@include": """
query BypassInclude($cond: Boolean!) {
  me @include(if: $cond) {
    id
    email
  }
}
""",
    "fragment_reuse": """
fragment UserFields on User {
  id
  email
}

query BypassFragment {
  me {
    ...UserFields
  }
}
""",
}

# GraphQL argument-mutation IDOR chain.
# Common field+argument shapes that map to a per-user / per-record object.
# We probe by issuing an introspection-style mutation and observing whether
# the response reveals field/argument structure that takes an identifier
# we can later substitute with another user's id.
GRAPHQL_ARGUMENT_FIELDS = [
    "user",
    "users",
    "account",
    "accounts",
    "order",
    "orders",
    "invoice",
    "invoices",
    "organization",
    "organizationUsers",
    "team",
    "members",
    "profile",
    "billing",
    "subscription",
    "project",
    "workspace",
    "document",
    "documents",
    "file",
    "files",
    "post",
    "posts",
    "comment",
    "comments",
    "message",
    "messages",
    "role",
    "permission",
    "apiKey",
    "token",
    "session",
    "device",
    "settings",
    "notification",
    "audit",
    "auditLog",
    "report",
    "reports",
    "dashboard",
    "widget",
    "integration",
    "webhook",
]

GRAPHQL_IDOR_ARGUMENTS = [
    "id",
    "ID",
    "userId",
    "user_id",
    "accountId",
    "account_id",
    "orgId",
    "org_id",
    "organizationId",
    "organization_id",
    "teamId",
    "team_id",
    "projectId",
    "project_id",
    "workspaceId",
    "workspace_id",
    "ownerId",
    "owner_id",
    "customerId",
    "customer_id",
    "clientId",
    "client_id",
    "orderId",
    "order_id",
    "invoiceId",
    "invoice_id",
]


# GET-based query templates. We URL-encode the query string and embed it
# in the path so we can confirm whether the server executes a GET GraphQL
# request without a CSRF token or non-empty Content-Type.
def _build_get_query_url(base_url: str, query: str) -> str:
    encoded = quote(query.strip(), safe="")
    sep = "&" if "?" in base_url else "?"
    return f"{base_url}{sep}query={encoded}"


# Cross-origin probe origins. If a GET-GraphQL endpoint accepts a request
# whose Origin matches a different host AND returns a 2xx, the endpoint
# is reachable from arbitrary attacker pages -> CSRF.
GRAPHQL_CSRF_ORIGINS = [
    "https://evil.example.com",
    "null",
    "https://attacker.tld",
]

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

_GRAPHQL_VERBOSE_ERROR_COMPILED = [
    re.compile(p, re.IGNORECASE) for p in GRAPHQL_VERBOSE_ERROR_PATTERNS
]


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


# GraphQL field suggestion brute-forcing words
GRAPHQL_COMMON_FIELDS = [
    "users",
    "admin",
    "settings",
    "me",
    "profile",
    "config",
    "debug",
    "secrets",
    "roles",
    "permissions",
]


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
    priority_urls: list[dict[str, Any]], response_cache: Any, limit: int = 8
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
                data = parsed.get("data") or {}
                if "data" in parsed and "__schema" in data:
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

        # Field Suggestion (If introspection failed/disabled)
        if "introspection_enabled" not in signals:
            suggested_fields = []
            for field in GRAPHQL_COMMON_FIELDS:
                field_resp = response_cache.request(
                    url,
                    method="POST",
                    headers={"Content-Type": "application/json", "Cache-Control": "no-cache"},
                    body=json.dumps({"query": f"{{ {field} {{ __typename }} }}"}),
                )
                if field_resp:
                    fb = str(field_resp.get("body_text") or "")
                    if "cannot query field" not in fb.lower() and "unknown type" not in fb.lower():
                        if "errors" in fb or "data" in fb:
                            suggested_fields.append(field)
            if suggested_fields:
                signals.append("field_suggestion_success")

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

        # Test 7: Directive-based access-control bypass
        # Send queries that use @skip(if: false) / @include(if: true) on
        # fields that are normally protected. If the server strips the auth
        # check when the field is "included" but not "executed" by the
        # client, we get a 200 with data we shouldn't see.
        directive_result: dict[str, Any] | None = None
        for directive_name, directive_query in GRAPHQL_DIRECTIVE_BYPASS_QUERIES.items():
            for cond_value in (True, False):
                dresp = response_cache.request(
                    url,
                    method="POST",
                    headers={
                        "Content-Type": "application/json",
                        "Cache-Control": "no-cache",
                        "X-GraphQL-Probe": f"directive_{directive_name}",
                    },
                    body=json.dumps({"query": directive_query, "variables": {"cond": cond_value}}),
                )
                if not dresp:
                    continue
                dbody = str(dresp.get("body_text") or "")
                dstatus = int(dresp.get("status_code") or 0)
                dparsed = _parse_graphql_response(dbody)
                if not dparsed:
                    continue
                data_obj = dparsed.get("data") if isinstance(dparsed, dict) else None
                if isinstance(data_obj, dict) and data_obj.get("me"):
                    signals.append(f"directive_bypass:{directive_name}")
                    directive_result = {
                        "status_code": dstatus,
                        "directive": directive_name,
                        "cond_value": cond_value,
                        "leaked_fields": list((data_obj.get("me") or {}).keys()),
                    }
                    break
            if directive_result:
                break

        # Test 8: GET-based query (CSRF amplification)
        # A GraphQL endpoint that accepts GET requests without a CSRF token
        # can be triggered cross-origin from any attacker-controlled page.
        # We send two GETs: one without an Origin, one with an evil Origin,
        # and a third with a 'text/plain' content-type POST (bypassing CORS
        # preflight). A 2xx on either is a finding.
        get_csrf_result: dict[str, Any] | None = None
        get_url = _build_get_query_url(url, "{ __typename }")
        baseline_get = response_cache.request(
            get_url,
            method="GET",
            headers={"Cache-Control": "no-cache", "X-GraphQL-Probe": "get_baseline"},
        )
        baseline_get_status = int((baseline_get or {}).get("status_code") or 0)
        baseline_get_data = ""
        if baseline_get:
            _b = _parse_graphql_response(str(baseline_get.get("body_text") or ""))
            if isinstance(_b, dict) and _b.get("data"):
                baseline_get_data = "data"

        # If GET works at all, try cross-origin
        if baseline_get_status and baseline_get_status < 400 and baseline_get_data:
            signals.append("graphql_get_accepted")
            for evil_origin in GRAPHQL_CSRF_ORIGINS:
                evil_resp = response_cache.request(
                    get_url,
                    method="GET",
                    headers={
                        "Origin": evil_origin,
                        "Referer": f"{evil_origin}/",
                        "Cache-Control": "no-cache",
                        "X-GraphQL-Probe": f"get_csrf_{evil_origin}",
                    },
                )
                if not evil_resp:
                    continue
                estatus = int(evil_resp.get("status_code") or 0)
                ebody = str(evil_resp.get("body_text") or "")
                if estatus and estatus < 400 and "__typename" in ebody:
                    signals.append("graphql_get_csrf_vulnerable")
                    get_csrf_result = {
                        "status_code": estatus,
                        "evil_origin": evil_origin,
                        "method": "GET",
                    }
                    break

        # Test 9: Argument-mutation IDOR chain.
        # Send a few common (field, idArg) mutations using probe values;
        # 200 with no auth error suggests the server will execute mutations
        # for arbitrary identifiers (foundation of an IDOR chain). We are
        # intentionally non-destructive: every payload is an introspection-
        # style / no-op mutation, never a real delete/update.
        idor_result: dict[str, Any] | None = None
        for field in GRAPHQL_ARGUMENT_FIELDS[:12]:  # cap to keep probe bounded
            probe_id = "1"
            probe_query = (
                f"mutation ProbeIdor {{ "
                f'delete{field.capitalize()}(id: "{probe_id}") {{ __typename }} '
                f"}}"
            )
            idor_resp = response_cache.request(
                url,
                method="POST",
                headers={
                    "Content-Type": "application/json",
                    "Cache-Control": "no-cache",
                    "X-GraphQL-Probe": f"idor_arg_{field}",
                },
                body=json.dumps({"query": probe_query}),
            )
            if not idor_resp:
                continue
            ibody = str(idor_resp.get("body_text") or "")
            istatus = int(idor_resp.get("status_code") or 0)
            iparsed = _parse_graphql_response(ibody)
            if not iparsed:
                continue
            idata = iparsed.get("data") if isinstance(iparsed, dict) else None
            ierrors = iparsed.get("errors") if isinstance(iparsed, dict) else None
            # Field-resolved successfully without an auth/forbidden error.
            if isinstance(idata, dict) and idata and not ierrors and istatus and istatus < 400:
                signals.append(f"idor_arg:{field}")
                idor_result = {
                    "status_code": istatus,
                    "field": field,
                    "executed": True,
                    "response_keys": list(idata.keys()),
                }
                break
            # Surface "argument not defined" patterns -> tells us the
            # mutation root is reachable but takes different arguments.
            if isinstance(ierrors, list) and ierrors:
                msgs = " ".join(
                    str(e.get("message", "")).lower() for e in ierrors if isinstance(e, dict)
                )
                if "cannot query field" in msgs or "unknown field" in msgs:
                    continue
                if "argument" in msgs and "required" in msgs:
                    signals.append(f"idor_arg:required_args:{field}")

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
        if any(s.startswith("directive_bypass:") for s in signals):
            risk_score += 7
        if "graphql_get_csrf_vulnerable" in signals:
            risk_score += 6
        if "graphql_get_accepted" in signals:
            risk_score += 2
        if any(s.startswith("idor_arg:") for s in signals):
            risk_score += 6

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
                "directive_result": directive_result,
                "get_csrf_result": get_csrf_result,
                "idor_result": idor_result,
            }
        )

    findings.sort(key=lambda item: (-item.get("risk_score", 0), item.get("url", "")))
    return findings
