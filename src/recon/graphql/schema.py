"""GraphQL schema constants and data structures."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# Default GraphQL endpoint paths to probe, in priority order.
DEFAULT_GRAPHQL_PATHS: tuple[str, ...] = (
    "/graphql",
    "/graphql/v1",
    "/graphql/v2",
    "/gql",
    "/api/graphql",
    "/api/gql",
    "/v1/graphql",
    "/v2/graphql",
    "/query",
    "/api/query",
    "/graphql/console",
    "/graphiql",
    "/playground",
    "/altair",
)

# Sanitised introspection query: we cap the depth and disable
# descriptions to keep the response small enough for production
# APIs that reject multi-megabyte schema dumps. Operators who need
# the full schema can run an external ``graphql-inspector`` against
# the saved endpoint URL.
_INTROSPECTION_QUERY: str = (
    "query IntrospectionQuery {"
    "  __schema {"
    "    queryType { name }"
    "    mutationType { name }"
    "    subscriptionType { name }"
    "    types {"
    "      kind name"
    "      fields(includeDeprecated: false) {"
    "        name args { name type { kind name ofType { kind name } } }"
    "        type { kind name ofType { kind name ofType { kind name } } }"
    "      }"
    "    }"
    "  }"
    "}"
)

# A minimal probe to detect "endpoint exists" without paying the cost
# of the full introspection query. Many production GraphQL APIs will
# return 200 with an error for an empty query; we look for that shape.
_PROBE_QUERY: str = '{"query":"{__typename}"}'

# Concurrent in-flight probes.
_PROBE_CONCURRENCY = 8

# Per-probe timeout in seconds.
_PROBE_TIMEOUT_SECONDS = 6

# Cap on introspection response body size (defends against runaway
# schemas being sent back). 1 MiB is enough for almost every public
# schema; operators with monster internal schemas can override via
# the ``graphql_introspection_max_bytes`` config key.
_MAX_INTROSPECTION_BYTES = 1 * 1024 * 1024

_ALIAS_TOKENS: tuple[str, ...] = (
    "email",
    "emails",
    "phone",
    "phones",
    "password",
    "passwords",
    "ssn",
    "social",
    "secret",
    "token",
    "tokens",
    "apiKey",
    "api_keys",
    "creditCard",
    "address",
    "billing",
    "payment",
    "balance",
    "transaction",
    "internal",
    "admin",
    "role",
    "permission",
    "permissions",
)

_TYPENAME_NESTED_DEPTHS: tuple[int, ...] = (2, 3, 4, 6, 8, 10)

_GRAPHQL_WS_PROTOCOLS: tuple[str, ...] = (
    "graphql-ws",
    "graphql-transport-ws",
)

_INTROSPECTION_BYPASS_FIELDS: tuple[str, ...] = (
    "__typename",
    "id",
    "_id",
    "createdAt",
    "updatedAt",
)

_FIELD_PROBE_FIELDS: tuple[str, ...] = (
    "__typename",
    "id",
    "name",
    "email",
    "username",
    "createdAt",
)

_CSRF_COOKIE_NAMES: tuple[str, ...] = (
    "sessionid",
    "session",
    "sid",
    "auth",
    "token",
    "access_token",
    "refresh_token",
    "connect.sid",
)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class GraphQLEndpoint:
    """A single GraphQL endpoint discovered for a host."""

    host: str
    url: str
    status_code: int = 0
    content_type: str = ""
    introspection_status: str = "unknown"
    schema_operations: dict[str, list[str]] = field(default_factory=dict)
    requires_auth: bool = False
    notes: list[str] = field(default_factory=list)
    attack_surface: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "url": self.url,
            "status_code": self.status_code,
            "content_type": self.content_type,
            "introspection_status": self.introspection_status,
            "schema_operations": {
                op: sorted(set(names)) for op, names in self.schema_operations.items()
            },
            "requires_auth": self.requires_auth,
            "notes": list(self.notes),
            "attack_surface": self.attack_surface,
        }
