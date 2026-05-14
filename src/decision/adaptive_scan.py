"""Adaptive scanning coordinator with priority-based target selection.

Implements the Naabu "predictive scan" pattern: instead of scanning all
targets in a fixed order, prioritize targets most likely to yield results
and dynamically boost correlated targets when vulnerabilities are found.

Key patterns from the Go codebase adapted for Python:
1. Priority-queue-based scanning (scan highest-risk first)
2. Correlation boosting (when vuln X found, boost targets with pattern X)
3. Early termination (stop when top targets are all low-risk)
4. Fast-path selection (use cached/simple probe when possible)
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class ScanResult:
    """Result of scanning a single target."""

    target: str
    success: bool
    findings: list[dict[str, Any]]
    duration_ms: float
    error: str = ""


@dataclass
class ScanBatchResult:
    """Result of a batch scan run."""

    total_targets: int
    scanned: int
    findings_count: int
    boosted_count: int
    early_terminated: bool
    duration_ms: float
    results: list[ScanResult]


class AdaptiveScanCoordinator:
    """Coordinates adaptive scanning with priority-based selection.

    Usage::

        coordinator = AdaptiveScanCoordinator(
            urls=urls,
            probe_fn=scan_url,  # async callable(urls) -> findings
            boost_on_findings=True,
            early_terminate=True,
        )
        result = await coordinator.run()
    """

    def __init__(
        self,
        urls: list[str],
        probe_fn: Callable,
        *,
        boost_on_findings: bool = True,
        early_terminate: bool = True,
        early_terminate_min: int = 5,
        early_terminate_ratio: float = 0.3,
        boost_factor: float = 2.0,
        batch_size: int = 50,
        max_batches: int | None = None,
        concurrency: int = 10,
    ) -> None:
        self._queue = CorrelationPriorityQueue.from_urls(
            urls,
            auto_correlate=boost_on_findings,
            boost_factor=boost_factor,
        )
        self._probe_fn = probe_fn
        self._early_terminate = early_terminate
        self._early_terminate_min = early_terminate_min
        self._early_terminate_ratio = early_terminate_ratio
        self._batch_size = batch_size
        self._max_batches = max_batches
        self._concurrency = concurrency
        self._results: list[ScanResult] = []
        self._total_findings: list[dict[str, Any]] = []

    async def run(self) -> ScanBatchResult:
        """Run the adaptive scan loop.

        Scans targets in priority order, boosting correlated targets
        when findings are discovered. Terminates early if remaining
        targets are all low-risk.
        """
        import time

        start = time.monotonic()
        batch_num = 0
        boosted_total = 0

        while True:
            # Check early termination
            if self._early_terminate and self._queue.should_terminate_early(
                min_items=self._early_terminate_min,
                threshold_ratio=self._early_terminate_ratio,
            ):
                logger.info(
                    "Adaptive scan: early termination after %d batches, "
                    "%d/%d targets scanned, %d findings",
                    batch_num,
                    len(self._results),
                    self._queue.total,
                    len(self._total_findings),
                )
                break

            # Check max batches
            if self._max_batches and batch_num >= self._max_batches:
                logger.info("Adaptive scan: reached max batch limit (%d)", self._max_batches)
                break

            # Get next batch of highest-priority targets
            batch_urls = []
            for _ in range(self._batch_size):
                target = self._queue.pop()
                if target is None:
                    break
                batch_urls.append((target, target.url))

            if not batch_urls:
                logger.info("Adaptive scan: all targets consumed")
                break

            batch_num += 1
            urls = [url for _, url in batch_urls]

            logger.info(
                "Adaptive scan batch %d: scanning %d targets (remaining: %d, findings so far: %d)",
                batch_num,
                len(urls),
                self._queue.remaining,
                len(self._total_findings),
            )

            # Scan the batch
            batch_results = await self._scan_batch(urls)
            self._results.extend(batch_results)

            # Collect findings and boost correlated targets
            batch_findings = []
            for result in batch_results:
                batch_findings.extend(result.findings)

            if batch_findings:
                self._total_findings.extend(batch_findings)
                boosted = self._queue.boost_from_findings(batch_findings)
                boosted_total += boosted
                logger.info(
                    "Batch %d: found %d findings, boosted %d correlated targets",
                    batch_num,
                    len(batch_findings),
                    boosted,
                )

        elapsed_ms = (time.monotonic() - start) * 1000

        return ScanBatchResult(
            total_targets=self._queue.total,
            scanned=len(self._results),
            findings_count=len(self._total_findings),
            boosted_count=boosted_total,
            early_terminated=self._queue.should_terminate_early(),
            duration_ms=round(elapsed_ms, 1),
            results=self._results,
        )

    async def _scan_batch(self, urls: list[str]) -> list[ScanResult]:
        """Scan a batch of URLs with controlled concurrency."""
        import time

        async def scan_one(url: str) -> ScanResult:
            start = time.monotonic()
            try:
                findings = await self._probe_fn(url)
                duration_ms = (time.monotonic() - start) * 1000
                return ScanResult(
                    target=url,
                    success=True,
                    findings=findings if isinstance(findings, list) else [],
                    duration_ms=round(duration_ms, 1),
                )
            except Exception as e:
                duration_ms = (time.monotonic() - start) * 1000
                return ScanResult(
                    target=url,
                    success=False,
                    findings=[],
                    duration_ms=round(duration_ms, 1),
                    error=str(e),
                )

        semaphore = asyncio.Semaphore(self._concurrency)

        async def bounded_scan(url: str) -> ScanResult:
            async with semaphore:
                return await scan_one(url)

        tasks = [bounded_scan(url) for url in urls]
        return await asyncio.gather(*tasks, return_exceptions=True)


# Import the priority queue (defined next)
from src.decision.priority_queue import CorrelationPriorityQueue
