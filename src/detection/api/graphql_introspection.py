"""GraphQL introspection query presence detector.

The detection layer previously had a passive detector
(:mod:`src.analysis.passive.detectors.detector_graphql`) that flags
GraphQL endpoints by URL pattern and looks for ``__schema``/``__type``
data in the response body. That works for endpoints that already leak
introspection data — it does not tell us whether the endpoint *would*
answer an introspection query.

This module closes the gap by detecting, in the response metadata we
already have access to, three concrete signals:

1. **Query language hints** — the response references the introspection
   query, the ``__schema`` selector, or contains a ``GraphQLError``
   with a ``query`` field.
2. **GraphiQL/Playground/Altair UI presence** — the response body
   contains a known GraphQL IDE bundle. The introspection endpoint is
   always available from inside the IDE.
3. **Persisted/disabled introspection** — the response body contains
   the ``"persistedQuery"`` token, the ``"disable"`` directive, or the
   Apollo persisted-query header. These tell us the introspection
   policy the API is enforcing.

The analyzer is intentionally pure-Python: it inspects the response
metadata (URL, headers, body, query parameters) and emits findings
without performing any network I/O. The exploitation layer can then
replay the introspection query through the dedicated
``graphql_active_probe`` binding.
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Pattern catalogue
# ---------------------------------------------------------------------------


# Substrings in the body that suggest the GraphQL IDE is exposed. Each
# one is a strong signal that introspection is reachable through the
# bundled UI.
_IDE_FINGERPRINTS: tuple[str, ...] = (
    "GraphiQL",
    "graphiql",
    "Apollo Studio",
    "Altair GraphQL Client",
    "graphql-playground",
    "GraphQL Playground",
    "graphiql.min.js",
    "react-graphiql",
    "altair-static",
)

# Introspection query fragments — found in proxy logs, devtools, and
# the GraphQL response body when introspection is enabled.
_INTROSPECTION_TOKENS: tuple[str, ...] = (
    "__schema",
    "__type",
    "__typename",
    "getIntrospectionQuery",
    "IntrospectionQuery",
)

# Tokens that indicate persisted query usage (APQ, Relay, Apollo
# Studio). These tell us the API enforces a query allow-list which
# means even disabled introspection is *intentionally* configured.
_PERSISTED_QUERY_TOKENS: tuple[str, ...] = (
    "persistedQuery",
    "extensions.persistedQuery",
    "APQ",
    "automaticPersistedQueries",
    "sha256Hash",
)

# Apollo / GraphQL specific response headers.
_INTROSPECTION_HEADERS: tuple[str, ...] = (
    "x-apollo-operation-name",
    "x-apollo-tracing",
    "graphql-response",
    "x-graphql-response",
)

# GraphQL endpoints we already know about, with a few extra
# non-obvious paths.
_ENDPOINT_HINTS: tuple[str, ...] = (
    "/graphql",
    "/api/graphql",
    "/v1/graphql",
    "/v2/graphql",
    "/gql",
    "/__graphql",
    "/graphiql",
    "/console/graphql",
    "/graphql/query",
    "/graphql/v1",
    "/graphql/v2",
    "/graphql/explorer",
    "/public/graphql",
    "/internal/graphql",
    "/admin/graphql",
    "/playground",
    "/altair",
)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class GraphQLIntrospectionFinding:
    """A single GraphQL introspection-related finding."""

    url: str
    endpoint_class: str
    introspection_signals: tuple[str, ...]
    ide_fingerprints: tuple[str, ...]
    persisted_query_signals: tuple[str, ...]
    introspection_headers: tuple[str, ...]
    severity: str
    confidence: float
    summary: str
    is_endpoint: bool
    has_ide: bool
    has_persisted_query: bool
    has_data_field: bool = False
    has_error_array: bool = False
    has_query_field: bool = False
    remediation_hint: str | None = None
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "indicator": "graphql_introspection_query_presence",
            "summary": self.summary,
            "severity": self.severity,
            "confidence": round(self.confidence, 3),
            "endpoint_class": self.endpoint_class,
            "is_endpoint": self.is_endpoint,
            "has_ide": self.has_ide,
            "has_persisted_query": self.has_persisted_query,
            "has_data_field": self.has_data_field,
            "has_error_array": self.has_error_array,
            "has_query_field": self.has_query_field,
            "introspection_signals": list(self.introspection_signals),
            "ide_fingerprints": list(self.ide_fingerprints),
            "persisted_query_signals": list(self.persisted_query_signals),
            "introspection_headers": list(self.introspection_headers),
            "remediation_hint": self.remediation_hint,
            "evidence": self.evidence,
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _endpoint_class(url: str) -> str:
    """Classify a URL as ``ide``, ``api``, ``probe`` or ``unknown``."""

    lowered = url.lower()
    if any(token in lowered for token in ("graphiql", "playground", "altair", "explorer")):
        return "ide"
    if any(token in lowered for token in ("/api/graphql", "/graphql", "/gql", "/__graphql")):
        return "api"
    return "unknown"


def _is_graphql_endpoint(url: str) -> bool:
    parsed = urlsplit(url)
    path = parsed.path.lower()
    return any(hint in path for hint in _ENDPOINT_HINTS)


def _scan_text(text: str, needles: Iterable[str]) -> tuple[str, ...]:
    lowered = text or ""
    return tuple(needle for needle in needles if needle in lowered)


def _scan_regex(text: str, patterns: Iterable[str]) -> tuple[str, ...]:
    hits: list[str] = []
    for pattern in patterns:
        match = re.search(pattern, text or "")
        if match:
            hits.append(pattern)
    return tuple(hits)


def _parse_json_body(body: str) -> Any | None:
    if not body:
        return None
    text = body.strip()
    if not text or text[0] not in "{[":
        return None
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        return None


# ---------------------------------------------------------------------------
# Core analysis
# ---------------------------------------------------------------------------


def analyze_graphql_introspection(
    *,
    url: str,
    body: str | None = None,
    headers: dict[str, Any] | None = None,
    query: str | None = None,
    response_status: int | None = None,
) -> GraphQLIntrospectionFinding:
    """Analyze a captured response (URL, body, headers) for GraphQL signals.

    Args:
        url: The URL the response came from.
        body: The response body as text (used for IDE/JSON introspection).
        headers: Optional dict of response headers (case-insensitive).
        query: Optional GraphQL ``query`` string used in the request.
        response_status: Optional HTTP status code for context.
    """

    body_text = body or ""
    header_dict = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    flattened_headers = "\n".join(f"{k}: {v}" for k, v in header_dict.items())
    search_blob = "\n".join(
        part for part in (body_text, flattened_headers, query or "") if part
    )

    introspection_signals = _scan_text(search_blob, _INTROSPECTION_TOKENS)
    ide_fingerprints = _scan_text(body_text, _IDE_FINGERPRINTS)
    persisted_query_signals = _scan_text(search_blob, _PERSISTED_QUERY_TOKENS)
    introspection_headers: list[str] = []
    for original_key in (headers or {}).keys():
        if str(original_key).lower() in _INTROSPECTION_HEADERS:
            introspection_headers.append(str(original_key))

    json_body = _parse_json_body(body_text)
    has_data_field = False
    has_error_array = False
    has_query_field = False
    if isinstance(json_body, dict):
        if "data" in json_body and isinstance(json_body["data"], (dict, list)):
            has_data_field = True
        errors = json_body.get("errors")
        if isinstance(errors, list) and errors:
            has_error_array = True
            for entry in errors:
                if isinstance(entry, dict) and "query" in entry:
                    has_query_field = True
                    persisted_query_signals = tuple(
                        dict.fromkeys((*persisted_query_signals, "error_query_field"))
                    )
        extensions = json_body.get("extensions")
        if isinstance(extensions, dict):
            for key, value in extensions.items():
                key_l = str(key).lower()
                if "persisted" in key_l or "tracing" in key_l or "cache" in key_l:
                    persisted_query_signals = tuple(
                        dict.fromkeys((*persisted_query_signals, key))
                    )
                if isinstance(value, dict):
                    for inner_key in value:
                        if "persisted" in str(inner_key).lower():
                            persisted_query_signals = tuple(
                                dict.fromkeys((*persisted_query_signals, inner_key))
                            )
    elif isinstance(json_body, list):
        if any(isinstance(item, dict) and "data" in item for item in json_body):
            has_data_field = True
        if any(
            isinstance(item, dict)
            and isinstance(item.get("errors"), list)
            and item["errors"]
            for item in json_body
            if isinstance(item, dict)
        ):
            has_error_array = True

    is_endpoint = _is_graphql_endpoint(url)
    has_ide = bool(ide_fingerprints)
    has_persisted_query = bool(persisted_query_signals)

    if has_ide and introspection_signals:
        severity = "high"
        confidence = 0.95
        summary = (
            f"GraphQL IDE exposed with active introspection at {url} "
            f"(signals: {', '.join(introspection_signals[:3])})"
        )
    elif has_ide:
        severity = "high"
        confidence = 0.85
        summary = (
            f"GraphQL IDE exposed at {url} — introspection reachable "
            "via the bundled UI."
        )
    elif introspection_signals and is_endpoint:
        severity = "high"
        confidence = 0.85
        summary = (
            f"GraphQL endpoint at {url} answered with introspection "
            f"data (signals: {', '.join(introspection_signals[:3])})"
        )
    elif introspection_signals and has_data_field:
        severity = "high"
        confidence = 0.80
        summary = (
            f"GraphQL introspection query returned a 'data' object at {url}."
        )
    elif introspection_signals and has_error_array:
        severity = "medium"
        confidence = 0.65
        summary = (
            f"GraphQL endpoint at {url} leaked GraphQLError details — "
            "introspection policy unclear."
        )
    elif has_error_array and is_endpoint and has_query_field:
        severity = "medium"
        confidence = 0.60
        summary = (
            f"GraphQL endpoint at {url} echoed the original query in "
            "its error response — introspection policy unclear."
        )
    elif has_persisted_query and is_endpoint:
        severity = "medium"
        confidence = 0.60
        summary = (
            f"GraphQL endpoint at {url} uses persisted queries; "
            "introspection policy must be confirmed via active probe."
        )
    elif is_endpoint:
        severity = "info"
        confidence = 0.50
        summary = f"GraphQL endpoint candidate at {url} (no introspection signal observed)."
    else:
        severity = "info"
        confidence = 0.20
        summary = f"No GraphQL introspection signal observed for {url}."

    endpoint_class = _endpoint_class(url)
    if endpoint_class == "unknown" and is_endpoint:
        endpoint_class = "api"

    evidence: dict[str, Any] = {
        "response_status": response_status,
        "query": query[:200] if query else None,
        "introspection_signal_count": len(introspection_signals),
        "ide_fingerprint_count": len(ide_fingerprints),
        "has_data_field": has_data_field,
        "has_error_array": has_error_array,
    }
    if introspection_headers:
        evidence["matched_headers"] = list(introspection_headers)

    remediation_hint = None
    if severity in {"high", "medium"}:
        remediation_hint = (
            "Disable introspection in production or restrict it to "
            "internal/admin routes; require explicit authentication "
            "and audit IDE deployments."
        )

    return GraphQLIntrospectionFinding(
        url=url,
        endpoint_class=endpoint_class,
        introspection_signals=introspection_signals,
        ide_fingerprints=ide_fingerprints,
        persisted_query_signals=persisted_query_signals,
        introspection_headers=tuple(introspection_headers),
        severity=severity,
        confidence=confidence,
        summary=summary,
        is_endpoint=is_endpoint,
        has_ide=has_ide,
        has_persisted_query=has_persisted_query,
        has_data_field=has_data_field,
        has_error_array=has_error_array,
        has_query_field=has_query_field,
        remediation_hint=remediation_hint,
        evidence=evidence,
    )


# ---------------------------------------------------------------------------
# Observation adapter
# ---------------------------------------------------------------------------


def graphql_introspection_findings_from_observations(
    observations: Iterable[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Convert [{url, body, headers, query, response_status}, ...] to findings."""

    findings: list[dict[str, Any]] = []
    for obs in observations:
        url = str(obs.get("url", "")).strip()
        if not url:
            continue
        body = obs.get("body_text") or obs.get("body") or obs.get("response_body")
        headers = obs.get("headers") or {}
        finding = analyze_graphql_introspection(
            url=url,
            body=str(body) if body else None,
            headers=dict(headers) if isinstance(headers, dict) else None,
            query=obs.get("query"),
            response_status=obs.get("status_code") or obs.get("response_status"),
        )
        findings.append(finding.to_dict())
    return findings


__all__ = [
    "GraphQLIntrospectionFinding",
    "analyze_graphql_introspection",
    "graphql_introspection_findings_from_observations",
]
