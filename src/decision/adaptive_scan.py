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
from typing import Any, Protocol, runtime_checkable

from src.decision.hunt_budget import HuntBudgetEnforcer
from src.decision.models import ScanPlan
from src.decision.priority_queue import CorrelationPriorityQueue


@runtime_checkable
class PriorityQueueProtocol(Protocol):
    """Protocol defining the operations required of an adaptive scan priority queue."""

    def pop(self) -> Any:
        ...

    def boost_from_findings(self, findings: list[dict[str, Any]]) -> list[str]:
        ...

    def should_terminate_early(
        self, threshold_ratio: float = 0.3, min_items: int = 5
    ) -> bool:
        ...

    def get_stats(self) -> dict[str, Any]:
        ...


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
    budget_snapshot: dict[str, Any] | None = None


class AdaptiveScanCoordinator:
    """Coordinates adaptive scanning with priority-based selection.

    Usage::

        coordinator = AdaptiveScanCoordinator(
            urls=urls,
            probe_fn=scan_url,  # async callable(urls) -> findings
            boost_on_findings=True,
            early_terminate=True,
            budget_enforcer=enforcer,
        )
        result = await coordinator.run()
    """

    def __init__(
        self,
        urls: list[str] | None = None,
        probe_fn: Callable = ...,
        *,
        queue: PriorityQueueProtocol | Any | None = None,
        boost_on_findings: bool = True,
        early_terminate: bool = True,
        early_terminate_min: int = 5,
        early_terminate_ratio: float = 0.3,
        boost_factor: float = 2.0,
        batch_size: int = 50,
        max_batches: int | None = None,
        concurrency: int = 10,
        budget_enforcer: HuntBudgetEnforcer | None = None,
    ) -> None:
        self._budget_enforcer = budget_enforcer
        if queue is not None:
            self._queue = queue
        else:
            self._queue = CorrelationPriorityQueue.from_urls(
                urls or [],
                auto_correlate=boost_on_findings,
                boost_factor=boost_factor,
                budget_enforcer=budget_enforcer,
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

    @classmethod
    def from_plan(
        cls,
        plan: ScanPlan,
        probe_fn: Callable,
        *,
        budget_enforcer: HuntBudgetEnforcer | None = None,
    ) -> AdaptiveScanCoordinator:
        """Create a coordinator instance from an immutable ScanPlan object."""
        return cls(
            urls=list(plan.targets),
            probe_fn=probe_fn,
            boost_on_findings=plan.boost_on_findings,
            early_terminate=plan.early_terminate,
            early_terminate_min=plan.early_terminate_min,
            early_terminate_ratio=plan.early_terminate_ratio,
            boost_factor=plan.boost_factor,
            batch_size=plan.batch_size,
            max_batches=plan.max_batches,
            concurrency=plan.concurrency,
            budget_enforcer=budget_enforcer,
        )

    @property
    def queue(self) -> PriorityQueueProtocol | Any:
        return self._queue

    @property
    def budget_enforcer(self) -> HuntBudgetEnforcer | None:
        return self._budget_enforcer

    @property
    def remaining(self) -> int:
        """Remaining target count in the priority queue."""
        if hasattr(self._queue, "remaining"):
            return self._queue.remaining
        return 0

    @property
    def total(self) -> int:
        """Total target count initialized in the priority queue."""
        if hasattr(self._queue, "total"):
            return self._queue.total
        return len(self._results)

    def peek_batch(self, batch_size: int | None = None) -> list[str]:
        """Inspect the next prioritized candidate targets without popping them."""
        limit = batch_size if batch_size is not None else self._batch_size
        if hasattr(self._queue, "peek_batch"):
            return self._queue.peek_batch(limit)
        elif hasattr(self._queue, "peek"):
            peeked = self._queue.peek()
            return [getattr(peeked, "url", str(peeked))] if peeked is not None else []
        return []

    def pop_batch(self, batch_size: int | None = None) -> list[str]:
        """Pop the next batch of prioritized candidate targets (Tier 3 Priority Engine)."""
        limit = batch_size if batch_size is not None else self._batch_size
        batch_urls: list[str] = []
        for _ in range(limit):
            target = self._queue.pop()
            if target is None:
                break
            url = getattr(target, "url", str(target))
            batch_urls.append(url)
        return batch_urls

    def boost_from_findings(self, findings: list[dict[str, Any]]) -> int:
        """Boost correlated targets in the priority queue from discovered findings."""
        if not findings:
            return 0
        if hasattr(self._queue, "boost_from_findings"):
            return self._queue.boost_from_findings(findings)
        return 0

    def should_terminate(self) -> bool:
        """Check if queue is exhausted or meets early-termination low-risk thresholds."""
        if hasattr(self._queue, "remaining") and self._queue.remaining == 0:
            return True
        if self._early_terminate and hasattr(self._queue, "should_terminate_early"):
            return self._queue.should_terminate_early(
                min_items=self._early_terminate_min,
                threshold_ratio=self._early_terminate_ratio,
            )
        return False

    async def run(
        self, save_delta_fn: Callable[[list[str], list[dict[str, Any]]], None] | None = None
    ) -> ScanBatchResult:
        """Run the adaptive scan loop.

        Scans targets in priority order, boosting correlated targets
        when findings are discovered. Terminates early if remaining
        targets are all low-risk.
        """
        import time

        start = time.monotonic()
        batch_num = 0
        boosted_total = 0
        early_terminated = False

        while True:
            # Bug #20 fix: previously the early-termination check ran at
            # the top of the loop, BEFORE the first batch was ever
            # popped. Combined with ``should_terminate_early`` returning
            # ``True`` for small queues, this caused the coordinator to
            # exit on iteration 0 without scanning anything. The check
            # is now performed AFTER the first batch is populated, so we
            # always make at least one pass over the priority queue.
            batch_urls: list[Any] = []
            for _ in range(self._batch_size):
                target = self._queue.pop()
                if target is None:
                    break
                batch_urls.append(target)

            if not batch_urls:
                logger.info(
                    "Adaptive scan: priority queue exhausted after %d batches, "
                    "%d/%d targets scanned, %d findings",
                    batch_num,
                    len(self._results),
                    self._queue.total,
                    len(self._total_findings),
                )
                break

            batch_num += 1
            urls = [target.url for target in batch_urls]

            logger.info(
                "Adaptive scan batch %d: scanning %d targets (remaining: %d, findings so far: %d)",
                batch_num,
                len(urls),
                self._queue.remaining,
                len(self._total_findings),
            )

            # Record/emit structured batch telemetry
            self._emit_batch_metrics(
                batch_num,
                len(urls),
                self._queue.remaining,
                len(self._total_findings),
            )

            # Finding 1: Replace asyncio.shield with a cancellation-aware
            # wrapper.  shield() creates zombie batches that continue
            # consuming resources after the pipeline is cancelled.
            # Instead, we run the batch with a timeout and explicitly
            # cancel the inner task when the outer is cancelled.
            if self._budget_enforcer:
                self._budget_enforcer.record_request(len(urls))

            cancelled = False
            _BATCH_TIMEOUT = 300.0  # 5 minutes per batch hard cap
            task = asyncio.create_task(self._scan_batch(urls))
            try:
                batch_results = await asyncio.wait_for(
                    asyncio.shield(task),
                    timeout=_BATCH_TIMEOUT,
                )
            except TimeoutError:
                logger.warning(
                    "Adaptive scan batch %d timed out after %.0fs; cancelling batch task",
                    batch_num,
                    _BATCH_TIMEOUT,
                )
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
                batch_results = []
                cancelled = True
            except asyncio.CancelledError:
                cancelled = True
                # Cancel the inner task to prevent zombie execution
                task.cancel()
                try:
                    batch_results = await task
                except asyncio.CancelledError:
                    batch_results = []

            self._results.extend(batch_results)

            # Collect findings and boost correlated targets
            batch_findings = []
            for result in batch_results:
                batch_findings.extend(result.findings)

            if batch_findings:
                self._total_findings.extend(batch_findings)
                if self._budget_enforcer:
                    for finding_item in batch_findings:
                        conf = float(finding_item.get("confidence", 0.8) or 0.8)
                        self._budget_enforcer.record_finding(conf)
                boosted = self._queue.boost_from_findings(batch_findings)
                boosted_total += boosted
                logger.info(
                    "Batch %d: found %d findings, boosted %d correlated targets",
                    batch_num,
                    len(batch_findings),
                    boosted,
                )

            # Flush the batch delta to checkpoint before potentially propagating cancellation
            if save_delta_fn:
                try:
                    save_delta_fn(urls, batch_findings)
                except Exception as exc:
                    logger.warning("Adaptive scan: failed to save batch checkpoint delta: %s", exc)

            if cancelled:
                logger.warning(
                    "Adaptive scan: execution cancelled, propagating cancellation after flushing batch delta"
                )
                raise asyncio.CancelledError()

            if self._max_batches and batch_num >= self._max_batches:
                logger.info("Adaptive scan: reached max batch limit (%d)", self._max_batches)
                break

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
                early_terminated = True
                break

        elapsed_ms = (time.monotonic() - start) * 1000

        return ScanBatchResult(
            total_targets=self._queue.total,
            scanned=len(self._results),
            findings_count=len(self._total_findings),
            boosted_count=boosted_total,
            early_terminated=early_terminated,
            duration_ms=round(elapsed_ms, 1),
            results=self._results,
            budget_snapshot=self._queue.budget_snapshot(),
        )

    def _emit_batch_metrics(
        self,
        batch_num: int,
        scanned_count: int,
        remaining_count: int,
        findings_count: int,
    ) -> None:
        """Emit structured telemetry metrics for batch scanning."""
        logger.info(
            "[Telemetry Metrics] batch=%d scanned=%d remaining=%d findings_total=%d",
            batch_num,
            scanned_count,
            remaining_count,
            findings_count,
        )

    async def _scan_batch(self, urls: list[str]) -> list[ScanResult]:
        """Scan a batch of URLs with controlled concurrency.

        Finding 6: Uses a semaphore-bounded worker pool instead of
        ``asyncio.gather(*tasks)`` to prevent creating thousands of
        coroutine objects simultaneously (which causes RAM spikes
        before any work starts).
        """
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
        processed_results: list[ScanResult] = []
        pending: set[asyncio.Task[ScanResult]] = set()

        async def bounded_scan(url: str) -> ScanResult:
            async with semaphore:
                return await scan_one(url)

        # Finding 6: Producer-consumer pattern with bounded concurrency.
        # Instead of creating all tasks at once (which allocates coroutine
        # objects for every URL), we maintain at most `concurrency` tasks
        # in flight simultaneously.
        url_iter = iter(urls)
        for url in url_iter:
            # Wait if we've hit the concurrency limit
            while len(pending) >= self._concurrency:
                done, pending = await asyncio.wait(
                    pending,
                    return_when=asyncio.FIRST_COMPLETED,
                )
                for completed_task in done:
                    try:
                        processed_results.append(completed_task.result())
                    except Exception as exc:
                        # Should not happen since scan_one catches all exceptions
                        logger.error("Unexpected task completion error: %s", exc)

            task = asyncio.create_task(bounded_scan(url))
            pending.add(task)

        # Drain remaining tasks
        if pending:
            done, _ = await asyncio.wait(pending)
            for completed_task in done:
                try:
                    processed_results.append(completed_task.result())
                except Exception as exc:
                    logger.error("Unexpected task completion error: %s", exc)

        return processed_results


# Import the priority queue (defined next)
logger = logging.getLogger(__name__)
