"""GraphQL introspection and endpoint discovery.

GraphQL endpoints are a major source of high-value bug-bounty findings.
Unlike REST APIs where the attack surface is determined by the URL
path, GraphQL exposes a single ``POST /graphql`` endpoint that can
invoke any query/mutation/subscription declared in the schema. The
schema is itself queryable via the standard introspection query —
which is enabled by default on the vast majority of public GraphQL
APIs.

This package:

1. **Probes candidate GraphQL endpoints** for a list of hosts. The
   default paths cover the most common conventions (``/graphql``,
   ``/gql``, ``/api/graphql``, ``/graphql/v1``, etc.) plus a small
   "maybe it's the same site at a different path" list.

2. **Runs a sanitised introspection query** (truncated to avoid
   giant schema dumps that fail on slow APIs) against each endpoint
   that responds with GraphQL-shaped content-type or with the
   sentinel ``"__schema"`` JSON key.

3. **Extracts the schema** as a structured dict with operations
   (queries / mutations / subscriptions), their arguments, and the
   return types. The output is suitable for direct Nuclei tag
   targeting (``graphql-introspect``, ``graphql-injection``,
   ``excessive-data-exposure``) and for hand-driven testing.

4. **Detects authorisation** by issuing a probe that exercises a
   benign field. The response is annotated with whether the server
   required authentication — useful for separating "open public API"
   from "needs a token" assets.

Attack-surface additions:

- **batching amplification** — probes whether the endpoint accepts a
  JSON array payload and returns batched responses, enabling cost
  amplification / DoS.
- **alias-based auth bypass** — inspects the schema for field aliases
  that point to sensitive data (email, password, token …) that may be
  reachable through a proxy-resistant alias.
- **Apollo Relay persisted-query analysis** — detects SHA-256 query
  allowlisting and the ``x-apollo-operation-name`` / ``apollo-hash``
  header patterns that indicate persisted-query enforcement.
- **GraphQL-over-WebSocket probe patterns** — checks for
  ``graphql-ws`` and ``graphql-transport-ws`` subprotocol support.
- **CSRF-style detection for cookie-authenticated endpoints** — sends
  a cheap graphql POST with a forged cookie header and looks for
  Set-Cookie responses that indicate server-side session state.
- **introspection bypass probing** — crawls nested ``__typename``
  queries at increasing depths to find where introspection data leaks
  through when the top-level ``__schema`` introspection is disabled.
- **production GraphQL Playground / GraphiQL exposure detection** —
  flags IDE endpoints.
- **field-level auth inference** — probes discovered fields with an
  anonymous token to surface which sensitive fields are actually
  accessible unauthenticated.
"""

from __future__ import annotations

from src.recon.graphql.analysis import (
    _alias_authorization_bypass,
    _check_apollo_persisted_query_headers,
    _detect_csrf_cookie_auth,
    _detect_graphql_ws,
    _probe_fields_for_auth_inference,
)
from src.recon.graphql.discovery import (
    _candidate_endpoint_urls,
    _normalize_base,
    discover_graphql_endpoints,
    filter_introspection_ok,
    summarize_endpoints,
)
from src.recon.graphql.introspection import (
    _GRAPHQL_INTROSPECTION_ERROR_RE,
    _GRAPHQL_KEY_RE,
    _build_nested_typename_query,
    _detect_debug_headers,
    _detect_merged_response_grid,
    _extract_operations,
    _introspect_endpoint_sync,
    _introspection_bypass_nested_typename,
    _looks_like_graphql,
    introspect_endpoint_async,
)
from src.recon.graphql.schema import (
    _ALIAS_TOKENS,
    _CSRF_COOKIE_NAMES,
    _FIELD_PROBE_FIELDS,
    _GRAPHQL_WS_PROTOCOLS,
    _INTROSPECTION_BYPASS_FIELDS,
    _INTROSPECTION_QUERY,
    _MAX_INTROSPECTION_BYTES,
    _PROBE_CONCURRENCY,
    _PROBE_QUERY,
    _PROBE_TIMEOUT_SECONDS,
    _TYPENAME_NESTED_DEPTHS,
    DEFAULT_GRAPHQL_PATHS,
    GraphQLEndpoint,
)

__all__ = [
    "DEFAULT_GRAPHQL_PATHS",
    "GraphQLEndpoint",
    "discover_graphql_endpoints",
    "filter_introspection_ok",
    "introspect_endpoint_async",
    "summarize_endpoints",
]
