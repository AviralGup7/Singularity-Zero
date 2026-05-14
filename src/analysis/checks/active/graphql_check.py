"""GraphQL Active Check - Introspection, depth abuse, batch aliasing, and mutation exposure.

Actively tests detected GraphQL endpoints for schema introspection exposure,
query depth abuse (DoS), batch query aliasing attacks, and dangerous mutation surfaces.
"""

import logging
from typing import Any
from urllib.parse import urlparse

from src.analysis.helpers import (
    build_endpoint_meta,
    endpoint_signature,
)
from src.analysis.helpers.scoring import severity_score
from src.analysis.json.graphql_introspection import (
    DANGEROUS_MUTATION_NAMES,
    detect_graphql_endpoints,
    test_batch_aliasing,
    test_introspection,
    test_mutation_exposure,
    test_query_depth,
)
from src.analysis.plugins import AnalysisPluginSpec

logger = logging.getLogger(__name__)

GRAPHQL_CHECK_SPEC = AnalysisPluginSpec(
    key="graphql_introspection_check",
    label="GraphQL Introspection & Schema Test",
    description="Detect GraphQL endpoints, test schema introspection exposure, query depth abuse, batch aliasing, and mutation surfaces.",
    group="active",
    slug="graphql_introspection_check",
    enabled_by_default=True,
)

_GRAPHQL_PATH_TOKENS = {"/graphql", "/graphiql", "/api/graphql", "/gql", "/query", "/api/query"}


def _is_graphql_url(url: str) -> bool:
    """Check if a URL looks like a GraphQL endpoint."""
    lowered = url.lower()
    return any(token in lowered for token in _GRAPHQL_PATH_TOKENS)


def _build_finding(
    url: str,
    severity: str,
    title: str,
    signals: list[str],
    evidence: dict[str, Any],
    explanation: str,
    status_code: int | None = None,
) -> dict[str, Any]:
    """Build a standardized finding dict."""
    meta = build_endpoint_meta(url)
    confidence_map = {"critical": 0.90, "high": 0.80, "medium": 0.65, "low": 0.50, "info": 0.30}
    return {
        "url": url,
        "endpoint_key": meta["endpoint_key"],
        "endpoint_base_key": meta["endpoint_base_key"],
        "endpoint_type": meta["endpoint_type"],
        "status_code": status_code,
        "category": "graphql_vulnerability",
        "title": title,
        "severity": severity,
        "confidence": confidence_map.get(severity, 0.50),
        "signals": sorted(set(signals)),
        "evidence": evidence,
        "explanation": explanation,
        "score": severity_score(severity),
    }


def graphql_introspection_check(
    priority_urls: list[dict[str, Any]] | None = None,
    response_cache: Any = None,
    urls: set[str] | None = None,
    responses: list[dict[str, Any]] | None = None,
    limit: int = 10,
) -> list[dict[str, Any]]:
    """Run GraphQL introspection and attack suite against detected endpoints.

    First attempts to auto-detect GraphQL endpoints from the crawled URLs,
    then runs introspection queries, depth abuse tests, batch aliasing,
    and mutation exposure checks.

    Args:
        priority_urls: List of URL dicts with endpoint metadata.
        response_cache: Response cache for making requests.
        urls: Set of URLs to scan for GraphQL endpoints.
        responses: List of HTTP response dicts.
        limit: Maximum number of endpoints to test.

    Returns:
        List of finding dicts for GraphQL vulnerabilities.
    """
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()

    candidate_urls: list[str] = []

    if priority_urls:
        for item in priority_urls:
            url = str(item.get("url", "")).strip()
            if url and _is_graphql_url(url):
                candidate_urls.append(url)

    if urls:
        for url in urls:
            if _is_graphql_url(url) and url not in candidate_urls:
                candidate_urls.append(url)

    if response_cache is not None and not candidate_urls:
        try:
            cached_urls = list(getattr(response_cache, "_url_cache", {}).keys())
        except Exception:
            cached_urls = []
        for url in cached_urls:
            if _is_graphql_url(url) and url not in candidate_urls:
                candidate_urls.append(url)

    if not candidate_urls and priority_urls:
        base_urls: list[str] = []
        seen_hosts: set[str] = set()
        for item in priority_urls[:50]:
            url = str(item.get("url", "")).strip()
            if not url:
                continue
            parsed = urlparse(url)
            host_key = f"{parsed.scheme}://{parsed.netloc}"
            if host_key not in seen_hosts:
                seen_hosts.add(host_key)
                base_urls.append(host_key)
        if base_urls:
            session = None
            if response_cache is not None:
                session = getattr(response_cache, "_session", None)
            if session is not None:
                detected = detect_graphql_endpoints(base_urls, session)
                candidate_urls = [d["url"] for d in detected]

    candidate_urls = candidate_urls[:limit]

    for url in candidate_urls:
        endpoint_key = endpoint_signature(url)
        if endpoint_key in seen:
            continue
        seen.add(endpoint_key)

        session = None
        if response_cache is not None:
            session = getattr(response_cache, "_session", None)
        if session is None:
            continue

        introspection = test_introspection(url, session)

        if introspection["introspection_enabled"]:
            signals = ["introspection_enabled", "schema_exposed"]
            severity = "high"
            mutation_names = introspection.get("mutations", [])
            dangerous_mutations = [
                m for m in mutation_names if m.lower() in DANGEROUS_MUTATION_NAMES
            ]
            if dangerous_mutations:
                signals.append("dangerous_mutations_in_schema")
                severity = "critical"

            findings.append(
                _build_finding(
                    url=url,
                    severity=severity,
                    title=f"GraphQL schema introspection enabled on {url}",
                    signals=signals,
                    evidence={
                        "type_count": introspection["type_count"],
                        "query_type": introspection["query_type"],
                        "mutation_type": introspection["mutation_type"],
                        "subscription_type": introspection["subscription_type"],
                        "mutations": mutation_names[:20],
                        "dangerous_mutations": dangerous_mutations,
                    },
                    explanation=(
                        f"The GraphQL endpoint at {url} returns full schema introspection data. "
                        f"Found {introspection['type_count']} types, query type: "
                        f"{introspection['query_type']}, mutation type: "
                        f"{introspection['mutation_type']}. "
                        f"{'Dangerous mutations detected: ' + ', '.join(dangerous_mutations[:5]) + '.' if dangerous_mutations else ''}"
                    ),
                    status_code=None,
                )
            )

        depth_result = test_query_depth(url, session, max_depth=10)

        if depth_result.get("dos_vulnerable"):
            findings.append(
                _build_finding(
                    url=url,
                    severity="medium",
                    title=f"GraphQL query depth not limited - DoS risk on {url}",
                    signals=["depth_limit_not_enforced", "dos_risk"],
                    evidence={
                        "max_successful_depth": depth_result["max_successful_depth"],
                        "depth_tests": depth_result.get("depth_tests", []),
                    },
                    explanation=(
                        f"The GraphQL endpoint at {url} accepts queries up to depth "
                        f"{depth_result['max_successful_depth']} without enforcing a depth limit. "
                        f"This could be exploited for denial-of-service via deeply nested queries."
                    ),
                    status_code=None,
                )
            )

        batch_result = test_batch_aliasing(url, session)

        if batch_result.get("batch_accepted"):
            findings.append(
                _build_finding(
                    url=url,
                    severity="medium",
                    title=f"GraphQL batch queries accepted on {url}",
                    signals=["batch_query_accepted", "rate_limit_bypass_risk"],
                    evidence={
                        "batch_size_accepted": batch_result["batch_size_accepted"],
                        "batch_tests": batch_result.get("batch_tests", []),
                    },
                    explanation=(
                        f"The GraphQL endpoint at {url} accepts batch queries (arrays of operations). "
                        f"Batch size of {batch_result['batch_size_accepted']} was accepted. "
                        f"This can be used to bypass rate limiting and amplify query costs."
                    ),
                    status_code=None,
                )
            )

        if batch_result.get("alias_abuse_accepted"):
            findings.append(
                _build_finding(
                    url=url,
                    severity="low",
                    title=f"GraphQL alias abuse accepted on {url}",
                    signals=["alias_abuse_accepted"],
                    evidence={
                        "alias_count_accepted": batch_result["alias_count_accepted"],
                    },
                    explanation=(
                        f"The GraphQL endpoint at {url} accepts queries with "
                        f"{batch_result['alias_count_accepted']} aliases in a single request. "
                        f"This can be used to amplify query costs within a single operation."
                    ),
                    status_code=None,
                )
            )

        mutation_result = test_mutation_exposure(url, session)

        if mutation_result.get("mutations_exposed") and not introspection.get(
            "introspection_enabled"
        ):
            findings.append(
                _build_finding(
                    url=url,
                    severity="low",
                    title=f"GraphQL mutation surface detected on {url}",
                    signals=["mutation_surface_detected"],
                    evidence={
                        "mutation_tests": mutation_result.get("mutation_tests", []),
                    },
                    explanation=(
                        f"The GraphQL endpoint at {url} accepts mutation operations. "
                        f"Full introspection was not available, but mutation execution was confirmed."
                    ),
                    status_code=None,
                )
            )

    findings.sort(
        key=lambda f: (
            {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(f["severity"], 5),
            -f["confidence"],
            f["url"],
        )
    )

    return findings[: limit * 3]
