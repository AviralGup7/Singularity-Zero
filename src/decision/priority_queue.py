"""Correlation-boosted priority queue for adaptive scanning.

Inspired by Naabu's predictive scan pattern: when a vulnerability is
discovered on one endpoint, correlated endpoints get boosted so they're
scanned sooner rather than later.

Similar to the Go ``portQueue`` which uses ``heapq`` with correlation
boosting from the ML prediction model, this module provides:

1. **Priority heap with dynamic boosting**: When findings arrive, related
   endpoints get boosted in the queue without full re-sort.
2. **Pattern-based correlation**: URLs sharing structure, params, or paths
   get correlated scores.
3. **Adaptive early termination**: If top-N items are all low-priority,
   scanning can stop early.

Thread-safe via ``threading.Lock`` for multi-producer (scanners emitting
findings) / single-consumer (scan coordinator pulling targets) usage.
"""

from __future__ import annotations

import heapq
import logging
import math
import threading
import time

try:
    import numpy as np

    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False
    np = None  # type: ignore[assignment]
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, urlparse

from src.infrastructure.scheduling.bidding import MultiObjectiveBid, bid_for_target
from src.learning.signal_quality import extract_features, ml_pipeline

logger = logging.getLogger(__name__)

# Imported lazily to avoid a circular import with
# ``src.decision.hunt_budget`` (which itself imports from this module
# for type-checking only).
try:
    from src.decision.hunt_budget import HuntBudgetEnforcer
except ImportError:  # pragma: no cover - defensive
    HuntBudgetEnforcer = None  # type: ignore[assignment,misc]


# URL pattern correlations: when this pattern is found on one endpoint,
# boost endpoints matching these patterns.
CORRELATION_RULES: list[tuple[str, list[str]]] = [
    # Auth endpoints often leak credentials on sibling endpoints
    ("/auth", ["/login", "/oauth", "/token", "/session", "/api/auth", "/api/login"]),
    # Upload endpoints suggest file handling siblings
    ("/upload", ["/file", "/attachment", "/document", "/import", "/export"]),
    # API endpoints often share authentication patterns
    ("/api/", ["/graphql", "/api/v", "/rest/", "/api/2", "/api/internal"]),
    # Admin panels suggest misconfigured sibling panels
    ("/admin", ["/dashboard", "/console", "/management", "/panel", "/settings"]),
    # Debug endpoints often leak info on siblings
    ("/debug", ["/health", "/metrics", "/swagger", "/actuator", "/env", "/config"]),
    # IDOR patterns: numeric IDs in one endpoint suggest others
    ("<id>", ["<id>", "<user>", "<account>", "<order>", "<profile>", "<object>"]),
]

# ID-like parameter patterns that suggest IDOR risk
IDOR_PARAM_PATTERNS: frozenset[str] = frozenset(
    {
        "id",
        "user",
        "account",
        "profile",
        "order",
        "object",
        "item",
        "customer",
        "record",
        "row",
        "entity",
        "doc",
        "document",
        "file",
        "group",
        "team",
    }
)

# SSRF-risk parameter patterns
SSRF_PARAM_PATTERNS: frozenset[str] = frozenset(
    {
        "url",
        "uri",
        "dest",
        "redirect",
        "target",
        "proxy",
        "domain",
        "feed",
        "callback",
        "next",
        "image",
        "path",
        "folder",
        "source",
        "file",
        "data",
        "load",
        "html",
        "page",
        "nav",
    }
)


@dataclass(order=False)
class ScanTarget:
    """A scanning target with dynamic priority and boost tracking.

    Similar to Go's ``pqItem`` but adapted for URL-based scanning
    rather than port-based scanning.

    Attributes:
        url: The target URL to scan.
        base_priority: Initial priority score (higher = more important).
        current_priority: Current effective priority (adjusted by boosts).
        findings_count: Number of findings already on this target.
        boost_factors: What caused priority boosts (for debugging/telemetry).
        scanned: Whether this target has been scanned.
        heap_idx: Position in the heap (used for O(log n) boosts).
    """

    url: str
    base_priority: float = 0.0
    current_priority: float = 0.0
    findings_count: int = 0
    boost_factors: list[str] = field(default_factory=list)
    scanned: bool = False
    heap_idx: int = -1
    metadata: dict[str, Any] = field(default_factory=dict)
    bid: MultiObjectiveBid | None = None
    created_at: float = field(default_factory=time.time)
    last_boosted_at: float | None = None

    @property
    def effective_priority(self) -> float:
        """Calculate effective priority using aging bonus and exponential decay of the boosted portion."""
        now = time.time()

        # Monotonically increasing aging factor to prevent starvation
        wait_time = max(0.0, now - self.created_at)
        aging_bonus = wait_time * 0.01

        # Exponential decay of the boosted portion (120s half-life)
        boosted_portion = self.current_priority - self.base_priority
        if boosted_portion > 0.0 and self.last_boosted_at is not None:
            time_since_boost = max(0.0, now - self.last_boosted_at)
            decay_factor = math.pow(2.0, -time_since_boost / 120.0)
            decayed_boost = boosted_portion * decay_factor
        else:
            decayed_boost = 0.0

        eff_priority = self.base_priority + decayed_boost + aging_bonus
        return min(max(0.0, eff_priority), 1000.0)

    def refresh_bid(self) -> MultiObjectiveBid:
        """Recompute the multi-objective bid for this target."""
        if "created_at" not in self.metadata:
            self.metadata["created_at"] = self.created_at
        self.bid = bid_for_target(
            url=self.url,
            base_priority=self.base_priority,
            current_priority=self.effective_priority,
            metadata=self.metadata,
        )
        return self.bid

    def apply_boost(self, factor: float, reason: str, max_boosts: int = 3) -> None:
        """Boost target priority while enforcing a cap of 5.0 * base_priority (min ceiling 50.0, global limit 1000.0)."""
        if len(self.boost_factors) >= max_boosts:
            return

        # Adjudication: limit individual boost intensity
        adjudicated_factor = max(0.1, min(factor, 5.0))
        old_priority = self.current_priority

        # Calculate new potential priority
        new_priority = self.current_priority * adjudicated_factor

        # Cap the boosted priority at 5x base_priority (min 50.0) and enforce global hard limit of 1000.0
        cap = min(max(5.0 * self.base_priority, 50.0), 1000.0)
        if new_priority > cap:
            new_priority = cap

        self.current_priority = new_priority
        self.last_boosted_at = time.time()
        # Bug #21 fix: previously ``self.boost_factors.append(reason)`` ran
        # unconditionally, so a no-op boost (priority already at the cap)
        # would still consume one of the ``max_boosts`` slots. A target
        # that has hit the cap with a real boost would then silently drop
        # subsequent genuine boosts because all its slots were burned.
        # Only record the boost if the priority actually changed.
        if reason and self.current_priority != old_priority:
            self.boost_factors.append(reason)
            if self.current_priority != old_priority:
                self.refresh_bid()

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, ScanTarget):
            return NotImplemented
        self_bid = self.bid or self.refresh_bid()
        other_bid = other.bid or other.refresh_bid()
        # heapq is a min-heap, so invert the bid score for max-heap behavior.
        if self_bid.score != other_bid.score:
            return self_bid.score > other_bid.score
        # Stable tie-breakers if heap_idx is not established (e.g. -1 for new items)
        if self.heap_idx != other.heap_idx and self.heap_idx != -1 and other.heap_idx != -1:
            return self.heap_idx < other.heap_idx
        if self.created_at != other.created_at:
            return self.created_at < other.created_at
        return id(self) < id(other)


def _url_patterns(url: str) -> dict[str, Any]:
    """Extract structural patterns from a URL for correlation matching.

    This is the Python equivalent of the Go ``parseIPv4Fast`` /
    ``targetIndex.pickIPv4`` ultra-fast parsing — but for URLs instead of IPs.

    Returns a dict with:
        - domain: the hostname
        - path_segments: list of path components
        - params: set of query parameter names
        - has_id_param: whether IDOR-like params are present
        - has_ssrf_param: whether SSRF-like params are present
    """
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    params = set(qs.keys())

    path_segments = [seg.lower() for seg in parsed.path.strip("/").split("/") if seg]

    return {
        "domain": parsed.hostname or "",
        "path_segments": path_segments,
        "params": params,
        "has_id_param": bool(params & IDOR_PARAM_PATTERNS),
        "has_ssrf_param": bool(params & SSRF_PARAM_PATTERNS),
    }


class CorrelationPriorityQueue:
    """Thread-safe priority queue with correlation-based boosting.

    This replaces the static ranking approach with a dynamic queue that
    adapts as findings come in — similar to how Naabu's ``portQueue``
    boosts correlated ports when open ports are discovered.

    Usage::

        pq = CorrelationPriorityQueue(urls)
        target = pq.pop()  # Get highest-priority target
        # ... scan target, emit findings ...
        pq.boost_from_findings(findings)  # Boost correlated targets
        target = pq.pop()  # Next target reflects boosted priorities
    """

    def __init__(
        self,
        targets: list[ScanTarget] | None = None,
        *,
        auto_correlate: bool = True,
        boost_factor: float = 2.0,
        budget_enforcer: HuntBudgetEnforcer | None = None,
    ) -> None:
        self._lock = threading.Lock()
        self._targets: list[ScanTarget] = []  # heap
        self._url_map: dict[str, ScanTarget] = {}  # url -> target
        self._patterns: dict[str, dict[str, Any]] = {}  # url -> extracted patterns list
        self._auto_correlate = auto_correlate
        self._boost_factor = boost_factor
        self._pop_count: int = 0
        self._total_findings: int = 0
        self._retraining_failures_count: int = 0
        self._budget_enforcer: HuntBudgetEnforcer | None = budget_enforcer
        if self._budget_enforcer is not None:
            self._budget_enforcer.bind_to_priority_queue(self)

        if targets:
            for i, t in enumerate(targets):
                t.heap_idx = i
                t.refresh_bid()
                heapq.heappush(self._targets, t)
                self._url_map[t.url] = t
                self._patterns[t.url] = _url_patterns(t.url)

    # ------------------------------------------------------------------
    # Construction helpers
    # ------------------------------------------------------------------

    @classmethod
    def from_urls(
        cls,
        urls: list[str],
        *,
        base_scores: dict[str, float] | None = None,
        auto_correlate: bool = True,
        boost_factor: float = 2.0,
        budget_enforcer: HuntBudgetEnforcer | None = None,
    ) -> CorrelationPriorityQueue:
        """Build a priority queue from a list of URLs.

        Args:
            urls: Target URLs to scan.
            base_scores: Optional pre-computed scores per URL.
            auto_correlate: Whether to auto-apply correlation boosting.
            boost_factor: Multiplier for correlation boosts.
            budget_enforcer: Optional :class:`HuntBudgetEnforcer` that
                gates ``should_terminate_early`` on time/requests/findings.
        """
        targets = []
        for url in urls:
            score = base_scores.get(url, 10.0) if base_scores else 10.0
            targets.append(ScanTarget(url=url, base_priority=score, current_priority=score))
        return cls(
            targets=targets,
            auto_correlate=auto_correlate,
            boost_factor=boost_factor,
            budget_enforcer=budget_enforcer,
        )

    # ------------------------------------------------------------------
    # Core queue operations
    # ------------------------------------------------------------------

    def pop(self) -> ScanTarget | None:
        """Remove and return the highest-priority target.

        Returns None if the queue is empty."""
        with self._lock:
            if not self._targets:
                return None
            self._targets[0].refresh_bid()
            if len(self._targets) > 1:
                heapq.heapify(self._targets)
            target = heapq.heappop(self._targets)
            target.scanned = True
            self._pop_count += 1
            return target

    def peek(self) -> ScanTarget | None:
        """Return the highest-priority target without removing it."""
        with self._lock:
            if not self._targets:
                return None
            self._targets[0].refresh_bid()
            if len(self._targets) > 1:
                heapq.heapify(self._targets)
            return self._targets[0] if self._targets else None

    def push(self, target: ScanTarget) -> None:
        """Add a new target to the queue.

        Useful when the scan dynamically discovers new targets to check."""
        with self._lock:
            target.refresh_bid()
            target.heap_idx = len(self._targets)
            heapq.heappush(self._targets, target)
            self._url_map[target.url] = target
            self._patterns[target.url] = _url_patterns(target.url)

    @property
    def remaining(self) -> int:
        """Number of unscanned targets remaining in the queue."""
        with self._lock:
            # Count only unscanned targets
            return len([t for t in self._targets if not t.scanned])

    @property
    def total(self) -> int:
        """Total number of targets ever added to the queue."""
        with self._lock:
            return len(self._url_map)

    # ------------------------------------------------------------------
    # Correlation boosting
    # ------------------------------------------------------------------

    def boost_url(self, url: str, factor: float = 2.0, reason: str = "") -> bool:
        """Boost a specific URL's priority.

        Args:
            url: Target URL to boost.
            factor: Priority multiplier (default 2x).
            reason: Description of why the boost was applied.

        Returns:
            True if the URL was found and boosted, False otherwise.
        """
        with self._lock:
            target = self._url_map.get(url)
            if target is None or target.scanned:
                return False
            old_priority = target.current_priority
            target.apply_boost(factor, reason)
            if target.current_priority != old_priority and target.heap_idx >= 0:
                idx = target.heap_idx
                if target.current_priority > old_priority:
                    heapq._siftdown(self._targets, 0, idx)  # type: ignore[attr-defined]
                else:
                    heapq._siftup(self._targets, idx)  # type: ignore[attr-defined]
            return True

    def boost_from_findings(
        self,
        findings: list[dict[str, Any]],
        *,
        boost_factor: float | None = None,
    ) -> int:
        """Boost correlated targets based on new findings.

        This is the equivalent of Naabu's ``boostCorrelated`` method,
        but for URL-based security scanning instead of port scanning.

        When a finding is discovered (e.g., SSRF on one endpoint),
        all endpoints that share similar characteristics (same params,
        similar path structure, etc.) get boosted to higher priority.

        Args:
            findings: List of finding dicts with url, category, severity.
            boost_factor: Override the queue's default boost factor.

        Returns:
            Number of targets that were boosted.
        """
        if not findings or not self._auto_correlate:
            return 0

        factor = boost_factor or self._boost_factor

        # Collect all finding characteristics
        boosted: set[str] = set()
        for finding in findings:
            finding_url = finding.get("url", "")
            if not finding_url:
                continue
            with self._lock:
                target = self._url_map.get(finding_url)
                if target:
                    target.findings_count += 1
            self._boost_related_urls(finding_url, finding, factor, boosted)
            with self._lock:
                self._total_findings += 1

        if boosted:
            with self._lock:
                heapq.heapify(self._targets)
            logger.info(
                "Boosted %d correlated targets from %d findings",
                len(boosted),
                len(findings),
            )

        # Trigger feedback retraining loop when findings are processed
        if findings:
            self.trigger_retraining_loop()

        return len(boosted)

    def _boost_related_urls(
        self,
        finding_url: str,
        finding: dict[str, Any],
        factor: float,
        boosted: set[str],
    ) -> None:
        """Boost URLs related to a finding's URL."""
        finding_patterns = _url_patterns(finding_url)
        finding_params = finding_patterns["params"]
        finding_path = finding_patterns["path_segments"]
        finding_category = finding.get("category", "").lower()

        with self._lock:
            for url, target in self._url_map.items():
                if target.scanned or url == finding_url or url in boosted:
                    continue

                url_patterns = self._patterns.get(url, _url_patterns(url))
                url_params = url_patterns["params"]
                url_path = url_patterns["path_segments"]

                # Rule 1: Same parameter overlap → likely same vulnerability class
                if finding_params and url_params:
                    overlap = finding_params & url_params
                    overlap_ratio = len(overlap) / max(len(finding_params | url_params), 1)
                    if overlap_ratio >= 0.5:
                        target.apply_boost(factor, f"param_overlap({', '.join(sorted(overlap))})")
                        boosted.add(url)
                        continue

                # Rule 2: Specific vulnerability-based correlations
                if finding_category and "ssrf" in finding_category:
                    if url_patterns["has_ssrf_param"]:
                        target.apply_boost(factor * 1.5, "ssrf_correlation")
                        boosted.add(url)
                        continue

                if finding_category and "idor" in finding_category:
                    if url_patterns["has_id_param"]:
                        target.apply_boost(factor * 1.5, "idor_correlation")
                        boosted.add(url)
                        continue

                # Rule 3: Path segment overlap
                if finding_path and url_path:
                    path_overlap = set(finding_path) & set(url_path)
                    if len(path_overlap) >= 2:
                        boost = factor * (0.8 + 0.2 * min(len(path_overlap) / 3, 1))
                        target.apply_boost(
                            boost, f"path_overlap({', '.join(sorted(path_overlap))})"
                        )
                        boosted.add(url)
                        continue

                # Rule 4: Generic correlation rules
                for trigger, related in CORRELATION_RULES:
                    if trigger == "<id>":
                        # ID-based correlation: any URL with ID-like params
                        if finding_params & IDOR_PARAM_PATTERNS and url_patterns["has_id_param"]:
                            target.apply_boost(factor * 0.8, "idor_pattern_match")
                            boosted.add(url)
                    else:
                        for segment in finding_path:
                            if trigger in segment:
                                for related_path in related:
                                    if any(related_path in ps for ps in url_path):
                                        target.apply_boost(factor * 0.5, f"rule_{trigger}"[:30])
                                        boosted.add(url)
                                        break

    # ------------------------------------------------------------------
    # Adaptive early termination
    # ------------------------------------------------------------------

    def should_terminate_early(
        self,
        *,
        min_items: int = 5,
        threshold_ratio: float = 0.3,
    ) -> bool:
        """Check if scanning should terminate early.

        If all remaining targets have priorities below the threshold_ratio
        of the highest initial priority, it means we've probably scanned
        everything important.

        Args:
            min_items: Minimum items remaining before considering termination.
            threshold_ratio: Priority threshold ratio (0.0-1.0).

        Returns:
            True if early termination is recommended.
        """
        if self._pop_count == 0:
            return False

        # Bug #19 fix: previously this method returned ``True`` whenever
        # ``remaining < min_items`` regardless of whether we had *scanned*
        # anything. We now only honour the low-count branch after at least
        # one full ``min_items`` of pops have occurred, so small queues
        # still drain. The remaining-count check is performed under the lock
        # to avoid TOCTOU races with concurrent pops.
        with self._lock:
            if (
                len([t for t in self._targets if not t.scanned]) < min_items
                and self._pop_count >= min_items
            ):
                return True
            max_base = max(t.base_priority for t in self._url_map.values())
            if max_base == 0:
                return False

            # Check if top remaining targets are all below threshold
            unscanned = sorted(
                [t for t in self._targets if not t.scanned],
                reverse=True,
            )
            if not unscanned:
                return True

            top_3_priorities = [t.current_priority for t in unscanned[:3]]
            threshold = max_base * threshold_ratio

            return all(p < threshold for p in top_3_priorities)

    # ------------------------------------------------------------------
    # Diagnostics
    # ------------------------------------------------------------------

    def get_stats(self) -> dict[str, Any]:
        """Return queue statistics for monitoring/debugging."""
        with self._lock:
            unscanned = [t for t in self._targets if not t.scanned]
            scanned = len(self._targets) - len(unscanned)
            boosted = sum(1 for t in self._targets if len(t.boost_factors) > 0)

            return {
                "total_targets": len(self._targets),
                "scanned": scanned,
                "remaining": len(unscanned),
                "boosted_targets": boosted,
                "total_findings_processed": self._total_findings,
                "pop_count": self._pop_count,
                "ml_retraining_failures": self._retraining_failures_count,
                "top_remaining": [
                    {
                        "url": t.url,
                        "priority": round(t.current_priority, 2),
                        "bid_score": round((t.bid or t.refresh_bid()).score, 3),
                        "boosts": len(t.boost_factors),
                    }
                    for t in heapq.nlargest(5, unscanned)
                ]
                if unscanned
                else [],
            }

    def set_budget_enforcer(self, enforcer: HuntBudgetEnforcer | None) -> None:
        """Attach (or replace) the budget enforcer that gates ``pop``.

        When an enforcer is attached, ``should_terminate_early`` will
        short-circuit to ``True`` as soon as any of the configured
        budget axes (time / requests / findings) is exhausted.
        """
        if (
            enforcer is not None
            and HuntBudgetEnforcer is not None
            and not isinstance(enforcer, HuntBudgetEnforcer)
        ):
            raise TypeError(
                f"enforcer must be a HuntBudgetEnforcer instance, got {type(enforcer).__name__}"
            )
        previous = self._budget_enforcer
        self._budget_enforcer = enforcer
        if enforcer is not None:
            enforcer.bind_to_priority_queue(self)
        elif previous is not None and hasattr(previous, "bind_to_priority_queue"):
            # Rebind with a no-op so the prior wrapper is no longer
            # pinning the closure of the previous enforcer.
            try:
                previous.bind_to_priority_queue(self)
            except Exception:  # pragma: no cover - defensive
                logger.debug("Rebind to priority queue failed for %s", previous, exc_info=True)
                pass

    def budget_snapshot(self) -> dict[str, Any] | None:
        if self._budget_enforcer is None:
            return None
        snap = self._budget_enforcer.snapshot()
        return {
            "budget": self._budget_enforcer.budget.to_dict(),
            **snap.to_dict(),
        }

    def trigger_retraining_loop(self) -> None:
        """Trigger incremental training of the ML quality model using queue targets and logs."""
        if not HAS_NUMPY or np is None:
            logger.warning("Feedback retraining skipped: numpy is not available")
            self._retraining_failures_count += 1
            return
        try:
            X: list[list[float]] = []
            y: list[int] = []

            with self._lock:
                for target in self._url_map.values():
                    # If target has findings_count > 0, it's a true positive example (label 1)
                    # If target has been scanned but findings_count == 0, it's a false positive example (label 0)
                    if target.scanned:
                        item = {
                            "url": target.url,
                            "confidence": target.base_priority / 100.0,
                            "finding_confidence": target.base_priority / 100.0,
                            "true_positive_probability": 0.9 if target.findings_count > 0 else 0.1,
                            "false_positive_probability": 0.1 if target.findings_count > 0 else 0.9,
                            "metadata": target.metadata,
                        }
                        features = extract_features(item)
                        X.append(features)
                        y.append(1 if target.findings_count > 0 else 0)

            if len(X) >= 5 and len(np.unique(y)) > 1:
                ml_pipeline.fit(np.array(X), np.array(y))
                logger.info(
                    "ML Quality Model incrementally retrained on %d samples from priority queue",
                    len(X),
                )
        except Exception as exc:
            logger.warning("Failed to trigger ML feedback retraining: %s", exc)
            self._retraining_failures_count += 1
