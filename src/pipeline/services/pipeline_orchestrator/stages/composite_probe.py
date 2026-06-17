"""Composite active probe for orchestrating multiple URL-level fuzzers."""

from __future__ import annotations

import asyncio
import os
from typing import Any

from src.core.logging.trace_logging import get_pipeline_logger

from .probe_runners import (
    _run_framing_fuzzer_probe,
    _run_fuzzing_suggestion_probe,
    _run_graphql_fuzzer_probe,
    _run_workflow_fuzzer_probe,
    _try_probe,
)
from .probe_suites import _run_auth_bypass_suite, _run_json_probe_suite

logger = get_pipeline_logger(__name__)

# Maximum number of concurrent probe tasks across all URLs in a single
# composite-probe invocation. Without this bound, a 200-URL target runs
# 12 probes per URL = 2 400 in-flight HTTP requests, exhausting connection
# pools and triggering target-side rate-limits. Tunable via
# ``COMPOSITE_PROBE_MAX_CONCURRENCY`` for ops rollback.
_DEFAULT_MAX_CONCURRENCY = 16


def _resolve_max_concurrency() -> int:
    raw = os.environ.get("COMPOSITE_PROBE_MAX_CONCURRENCY")
    if raw is None:
        return _DEFAULT_MAX_CONCURRENCY
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return _DEFAULT_MAX_CONCURRENCY
    return max(1, value)


class CompositeActiveProbe:
    """Combines multiple active probes into a single callable for AdaptiveScanCoordinator."""

    def __init__(
        self,
        probes: dict[str, Any],
        response_cache: Any,
        timeout_seconds: float = 180.0,
        error_accumulator: list[dict[str, Any]] | None = None,
    ) -> None:
        self.probes = probes
        self.response_cache = response_cache
        self.timeout_seconds = timeout_seconds
        self.error_accumulator = error_accumulator
        # One semaphore per CompositeActiveProbe instance, so the
        # AdaptiveScanCoordinator can still multiplex several URLs in
        # parallel but no single URL fans out unbounded.
        self._max_concurrency = _resolve_max_concurrency()

    async def __call__(self, url: str) -> list[dict[str, Any]]:
        """Run all relevant endpoint-level probes for a single URL."""
        item = {"url": url}
        url_l = [url]
        item_l = [item]

        # We run endpoint-focused probes here.
        # Host-focused probes (like Cloud Metadata) are better handled separately
        # to avoid redundant scanning.

        probe_names = [
            "sqli",
            "csrf",
            "jwt",
            "xss",
            "ssrf",
            "idor",
            "hpp",
            "graphql",
            "auth_bypass",
            "json",
            "fuzzing_suggestions",
            "fuzzing_campaign",
            "workflow_fuzzer",
            "graphql_fuzzer",
            "framing_fuzzer",
        ]
        tasks = [
            _try_probe(
                "sqli",
                self.probes["sqli_safe_probe"],
                item_l,
                self.response_cache,
                timeout_seconds=self.timeout_seconds,
                error_accumulator=self.error_accumulator,
            ),
            _try_probe(
                "csrf",
                self.probes["csrf_active_probe"],
                item_l,
                self.response_cache,
                timeout_seconds=self.timeout_seconds,
                error_accumulator=self.error_accumulator,
            ),
            _try_probe(
                "jwt",
                self.probes["jwt_manipulation_probe"],
                item_l,
                self.response_cache,
                timeout_seconds=self.timeout_seconds,
                error_accumulator=self.error_accumulator,
            ),
            _try_probe(
                "xss",
                self.probes["xss_reflect_probe"],
                item_l,
                self.response_cache,
                4,
                timeout_seconds=self.timeout_seconds,
                error_accumulator=self.error_accumulator,
            ),
            _try_probe(
                "ssrf",
                self.probes["ssrf_active_probe"],
                item_l,
                self.response_cache,
                4,
                timeout_seconds=self.timeout_seconds,
                error_accumulator=self.error_accumulator,
            ),
            _try_probe(
                "idor",
                self.probes["idor_active_probe"],
                item_l,
                self.response_cache,
                timeout_seconds=self.timeout_seconds,
                error_accumulator=self.error_accumulator,
            ),
            _try_probe(
                "hpp",
                self.probes["hpp_active_probe"],
                item_l,
                self.response_cache,
                timeout_seconds=self.timeout_seconds,
                error_accumulator=self.error_accumulator,
            ),
            _try_probe(
                "graphql",
                self.probes["graphql_active_probe"],
                item_l,
                self.response_cache,
                timeout_seconds=self.timeout_seconds,
                error_accumulator=self.error_accumulator,
            ),
            _try_probe(
                "auth_bypass",
                _run_auth_bypass_suite,
                item_l,
                self.response_cache,
                6,
                timeout_seconds=self.timeout_seconds,
                probes=self.probes,
                error_accumulator=self.error_accumulator,
            ),
            _try_probe(
                "json",
                _run_json_probe_suite,
                url_l,
                self.response_cache,
                timeout_seconds=self.timeout_seconds,
                probes=self.probes,
                error_accumulator=self.error_accumulator,
            ),
            _try_probe(
                "fuzzing_suggestions",
                _run_fuzzing_suggestion_probe,
                url_l,
                6,
                timeout_seconds=self.timeout_seconds,
                probes=self.probes,
                error_accumulator=self.error_accumulator,
            ),
            _try_probe(
                "fuzzing_campaign",
                self.probes["run_fuzzing_campaign_probe"],
                url_l,
                6,
                timeout_seconds=self.timeout_seconds,
                probes=self.probes,
                error_accumulator=self.error_accumulator,
            ),
            _try_probe(
                "workflow_fuzzer",
                _run_workflow_fuzzer_probe,
                item_l,
                self.response_cache,
                8,
                timeout_seconds=self.timeout_seconds,
                probes=self.probes,
                error_accumulator=self.error_accumulator,
            ),
            _try_probe(
                "graphql_fuzzer",
                _run_graphql_fuzzer_probe,
                item_l,
                self.response_cache,
                6,
                timeout_seconds=self.timeout_seconds,
                probes=self.probes,
                error_accumulator=self.error_accumulator,
            ),
            _try_probe(
                "framing_fuzzer",
                _run_framing_fuzzer_probe,
                item_l,
                self.response_cache,
                6,
                timeout_seconds=self.timeout_seconds,
                probes=self.probes,
                error_accumulator=self.error_accumulator,
            ),
        ]

        # Bounded fan-out: at most ``max_concurrency`` probe tasks may be
        # in flight at once. ``asyncio.Semaphore`` is the right primitive
        # because the probe coroutines are CPU/IO mixed and the limit
        # is independent of the connection pool size configured on
        # ``response_cache``. ``AdaptiveScanCoordinator`` may invoke this
        # callable for many URLs in parallel, but the per-instance
        # semaphore prevents the inner ``tasks`` list from running
        # unboundedly.
        semaphore = asyncio.Semaphore(self._max_concurrency)

        async def _bounded(coro: Any) -> Any:
            async with semaphore:
                return await coro

        bounded_tasks = [_bounded(t) for t in tasks]
        results = await asyncio.gather(*bounded_tasks, return_exceptions=True)

        all_findings = []
        for probe_name, r in zip(probe_names, results, strict=False):
            if isinstance(r, BaseException):
                logger.error("Active scan probe '%s' failed: %s", probe_name, r)
                if self.error_accumulator is not None:
                    self.error_accumulator.append(
                        {
                            "probe": probe_name,
                            "reason": "error",
                            "message": f"Active scan probe '{probe_name}' failed: {r}",
                        }
                    )
                continue
            if isinstance(r, tuple):
                _, findings, ok = r
                if ok and findings:
                    all_findings.extend(findings)

        return all_findings
