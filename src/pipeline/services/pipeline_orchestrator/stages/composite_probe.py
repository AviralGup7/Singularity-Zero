"""Composite active probe for orchestrating multiple URL-level fuzzers."""

from __future__ import annotations

import asyncio
from typing import Any

from src.core.logging.trace_logging import get_pipeline_logger

from .probe_runners import _run_fuzzing_suggestion_probe, _try_probe
from .probe_suites import _run_auth_bypass_suite, _run_json_probe_suite

logger = get_pipeline_logger(__name__)


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
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

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
