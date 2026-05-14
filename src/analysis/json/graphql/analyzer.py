"""Main orchestrator for GraphQL introspection analysis.

Coordinates endpoint detection, schema introspection, depth testing,
batch/alias testing, mutation exposure checks, and vulnerability analysis.
"""

import logging
from typing import Any

from .schema_parser import (
    detect_graphql_endpoints,
)
from .vulnerability_checker import (
    build_summary,
    collect_all_findings,
    test_batch_aliasing,
    test_introspection,
    test_mutation_exposure,
    test_query_depth,
)

logger = logging.getLogger(__name__)


def run_graphql_analysis(
    urls: list[str], session, config: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Main entry point for GraphQL introspection analysis."""
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

        depth_result = test_query_depth(ep_url, session, max_depth=max_depth)
        ep_result["depth_test"] = depth_result

        batch_result = test_batch_aliasing(ep_url, session)
        ep_result["batch_aliasing"] = batch_result

        mutation_result = test_mutation_exposure(ep_url, session)
        ep_result["mutation_exposure"] = mutation_result

        endpoint_findings = collect_all_findings(ep_url, introspection, depth_result, batch_result)
        all_findings.extend(endpoint_findings)
        endpoint_results.append(ep_result)

    summary = build_summary(endpoint_results, len(all_findings))

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
