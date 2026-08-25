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
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Protocol
from urllib.parse import parse_qs, urlparse

from src.decision.models import CandidateLease

logger = logging.getLogger(__name__)


class BidProtocol(Protocol):
    """Structural protocol for bid objects."""

    score: float


BidCalculator = Callable[..., Any]


def _default_bid_calculator(
    url: str,
    base_priority: float,
    current_priority: float,
    metadata: dict[str, Any],
) -> Any:
    """Lazy resolver for target bidding to decouple infrastructure scheduling."""
    try:
        from src.infrastructure.scheduling.bidding import bid_for_target

        return bid_for_target(
            url=url,
            base_priority=base_priority,
            current_priority=current_priority,
            metadata=metadata,
        )
    except Exception:

        class _SimpleBid:
            __slots__ = ("score",)

            def __init__(self, score: float) -> None:
                self.score = score

        return _SimpleBid(score=current_priority)


# Imported lazily or typed cleanly to avoid a circular import with
# ``src.decision.hunt_budget``.
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
    bid: Any | None = None
    bid_calculator: BidCalculator | None = None
    created_at: float = field(default_factory=time.time)
    last_boosted_at: float | None = None
    lease_expires_at: float = 0.0
    candidate_id: str = ""
    lease_id: str = ""
    lease_worker_id: str = ""
    execution_id: str = ""

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

    def refresh_bid(self) -> Any:
        """Recompute the multi-objective bid for this target."""
        if "created_at" not in self.metadata:
            self.metadata["created_at"] = self.created_at
        calc = self.bid_calculator or _default_bid_calculator
        self.bid = calc(
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

        # Compute current effective base before applying new boost to prevent resurrecting decayed boosts
        now = time.time()
        boosted_portion = max(0.0, self.current_priority - self.base_priority)
        if boosted_portion > 0.0 and self.last_boosted_at is not None:
            time_since_boost = max(0.0, now - self.last_boosted_at)
            decay_factor = math.pow(2.0, -time_since_boost / 120.0)
            current_active = self.base_priority + (boosted_portion * decay_factor)
        else:
            current_active = self.current_priority

        # Calculate new potential priority from active priority level
        new_priority = max(self.base_priority, current_active) * adjudicated_factor

        # Cap the boosted priority at 5x base_priority (min 50.0) and enforce global hard limit of 1000.0
        cap = min(max(5.0 * self.base_priority, 50.0), 1000.0)
        if new_priority > cap:
            new_priority = cap

        self.current_priority = new_priority
        self.last_boosted_at = time.time()

        if self.current_priority != old_priority:
            if reason:
                self.boost_factors.append(reason)
            self.refresh_bid()

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, ScanTarget):
            return NotImplemented
        self_bid = self.bid or self.refresh_bid()
        other_bid = other.bid or other.refresh_bid()
        # heapq is a min-heap, so invert the bid score for max-heap behavior.
        if self_bid.score != other_bid.score:
            return bool(self_bid.score > other_bid.score)
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
        bid_calculator: BidCalculator | None = None,
        policy: Any | None = None,
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
        self._budget_enforcer_hook: HuntBudgetEnforcer | None = budget_enforcer
        self._bid_calculator: BidCalculator | None = bid_calculator
        self._policy: Any | None = policy
        self._policy_version: str = getattr(policy, "version", "") if policy else ""

        if targets:
            for i, t in enumerate(targets):
                t.heap_idx = i
                if bid_calculator is not None and t.bid_calculator is None:
                    t.bid_calculator = bid_calculator
                t.refresh_bid()
                heapq.heappush(self._targets, t)
                self._url_map[t.url] = t
                self._patterns[t.url] = _url_patterns(t.url)

        if policy is not None:
            self.apply_versioned_policy(policy)

    @property
    def policy_version(self) -> str:
        return self._policy_version

    def apply_versioned_policy(self, policy: Any) -> int:
        """Apply target boosts and suppressions from an immutable VersionedPolicy."""
        applied_count = 0
        with self._lock:
            self._policy = policy
            self._policy_version = getattr(policy, "version", "1.0.0")
            boosts = dict(getattr(policy, "target_boosts", ()))
            suppressions = dict(getattr(policy, "target_suppressions", ()))

            for target in self._targets:
                if target.url in boosts:
                    target.current_priority += boosts[target.url]
                    target.boost_factors.append(f"policy_boost:{self._policy_version}")
                    applied_count += 1
                elif any(pattern in target.url for pattern in boosts):
                    for p, b in boosts.items():
                        if p in target.url:
                            target.current_priority += b
                            target.boost_factors.append(f"policy_pattern_boost:{p}")
                            applied_count += 1
                            break

                if target.url in suppressions:
                    target.current_priority = max(
                        0.0, target.current_priority + suppressions[target.url]
                    )
                    target.boost_factors.append(f"policy_suppress:{self._policy_version}")
                    applied_count += 1
                elif any(pattern in target.url for pattern in suppressions):
                    for p, s in suppressions.items():
                        if p in target.url:
                            target.current_priority = max(0.0, target.current_priority + s)
                            target.boost_factors.append(f"policy_pattern_suppress:{p}")
                            applied_count += 1
                            break

            self._refresh_heap()
        return applied_count

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
        bid_calculator: BidCalculator | None = None,
    ) -> CorrelationPriorityQueue:
        """Build a priority queue from a list of URLs.

        Args:
            urls: Target URLs to scan.
            base_scores: Optional pre-computed scores per URL.
            auto_correlate: Whether to auto-apply correlation boosting.
            boost_factor: Multiplier for correlation boosts.
            budget_enforcer: Optional :class:`HuntBudgetEnforcer` that
                gates ``should_terminate_early`` on time/requests/findings.
            bid_calculator: Optional custom bid calculator callable.
        """
        targets = []
        for url in urls:
            score = base_scores.get(url, 10.0) if base_scores else 10.0
            targets.append(
                ScanTarget(
                    url=url,
                    base_priority=score,
                    current_priority=score,
                    bid_calculator=bid_calculator,
                )
            )
        return cls(
            targets=targets,
            auto_correlate=auto_correlate,
            boost_factor=boost_factor,
            budget_enforcer=budget_enforcer,
            bid_calculator=bid_calculator,
        )

    # ------------------------------------------------------------------
    # Core queue operations
    # ------------------------------------------------------------------

    def _refresh_heap(self) -> None:
        """Recompute bids and restore heap order after aging/decay."""
        for target in self._targets:
            target.refresh_bid()
        heapq.heapify(self._targets)
        for index, target in enumerate(self._targets):
            target.heap_idx = index

    def pop(self) -> ScanTarget | None:
        """Remove and return the highest-priority target.

        Returns None if the queue is empty."""
        with self._lock:
            if not self._targets:
                return None
            self._refresh_heap()
            target = heapq.heappop(self._targets)
            for index, remaining in enumerate(self._targets):
                remaining.heap_idx = index
            target.scanned = True
            self._pop_count += 1
            return target

    def peek(self) -> ScanTarget | None:
        """Return the highest-priority target without removing it."""
        with self._lock:
            if not self._targets:
                return None
            self._refresh_heap()
            return self._targets[0]

    def peek_batch(self, limit: int = 10) -> list[str]:
        """Return the top N unscanned targets without removing them."""
        with self._lock:
            if not self._targets:
                return []
            self._refresh_heap()
            now = time.time()
            sorted_unscanned = sorted(
                [t for t in self._targets if not t.scanned and t.lease_expires_at <= now],
                key=lambda t: t.effective_priority,
                reverse=True,
            )
            return [t.url for t in sorted_unscanned[:limit]]

    def lease_batch(
        self,
        limit: int = 10,
        lease_timeout_seconds: float = 60.0,
        worker_id: str = "worker_default",
        execution_id: str = "",
    ) -> list[CandidateLease]:
        """Lease the top N unscanned targets, marking them in-flight with a unique lease token."""
        with self._lock:
            if not self._targets:
                return []
            self._refresh_heap()
            now = time.time()
            available = sorted(
                [t for t in self._targets if not t.scanned and t.lease_expires_at <= now],
                key=lambda t: t.effective_priority,
                reverse=True,
            )
            leases: list[CandidateLease] = []
            for target in available[:limit]:
                target.lease_expires_at = now + lease_timeout_seconds
                target.candidate_id = target.candidate_id or f"cand_{uuid.uuid4().hex[:12]}"
                target.lease_id = f"lease_{uuid.uuid4().hex[:12]}"
                target.lease_worker_id = worker_id
                target.execution_id = execution_id
                leases.append(
                    CandidateLease(
                        candidate_id=target.candidate_id,
                        target_url=target.url,
                        execution_id=execution_id,
                        lease_id=target.lease_id,
                        worker_id=worker_id,
                        expires_at=target.lease_expires_at,
                    )
                )
            return leases

    def ack_batch(self, items: list[CandidateLease | str]) -> int:
        """Acknowledge completed execution of targets, verifying lease identity."""
        acked_count = 0
        with self._lock:
            for item in items:
                if isinstance(item, CandidateLease):
                    target = self._url_map.get(item.target_url)
                    if target and not target.scanned:
                        # Enforce lease identity: reject stale or expired worker acks
                        if target.lease_id != item.lease_id:
                            logger.warning(
                                "Stale lease ack rejected for target %s: expected lease %s, got %s",
                                item.target_url,
                                target.lease_id,
                                item.lease_id,
                            )
                            continue
                        target.scanned = True
                        target.lease_expires_at = 0.0
                        target.lease_id = ""
                        self._pop_count += 1
                        acked_count += 1
                elif isinstance(item, str):
                    target = self._url_map.get(item)
                    if target and not target.scanned:
                        target.scanned = True
                        target.lease_expires_at = 0.0
                        target.lease_id = ""
                        self._pop_count += 1
                        acked_count += 1
        return acked_count

    def release_batch(self, items: list[CandidateLease | str]) -> int:
        """Release leased targets back to available pool if execution failed before completion."""
        released_count = 0
        with self._lock:
            for item in items:
                if isinstance(item, CandidateLease):
                    target = self._url_map.get(item.target_url)
                    if target and not target.scanned:
                        if target.lease_id == item.lease_id:
                            target.lease_expires_at = 0.0
                            target.lease_id = ""
                            released_count += 1
                elif isinstance(item, str):
                    target = self._url_map.get(item)
                    if target and not target.scanned:
                        target.lease_expires_at = 0.0
                        target.lease_id = ""
                        released_count += 1
        return released_count

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

        Checks the budget enforcer first (if bound), then falls through
        to the heuristic: if all remaining targets have priorities below
        the threshold_ratio of the highest initial priority, it means
        we've probably scanned everything important.

        Args:
            min_items: Minimum items remaining before considering termination.
            threshold_ratio: Priority threshold ratio (0.0-1.0).

        Returns:
            True if early termination is recommended.
        """
        if self._pop_count == 0:
            return False

        hook = getattr(self, "_budget_enforcer_hook", None)
        if hook is not None and hook.is_exhausted():
            hook.mark_terminated("budget_exhausted")
            return True

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
                key=lambda t: (t.bid or t.refresh_bid()).score,
                reverse=True,
            )
            if not unscanned:
                return True

            top_3_priorities = [t.effective_priority for t in unscanned[:3]]
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
            top_5 = sorted(
                unscanned,
                key=lambda t: (t.bid or t.refresh_bid()).score,
                reverse=True,
            )[:5]

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
                        "effective_priority": round(t.effective_priority, 2),
                        "bid_score": round((t.bid or t.refresh_bid()).score, 3),
                        "boosts": len(t.boost_factors),
                    }
                    for t in top_5
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
        self._budget_enforcer = enforcer
        self._budget_enforcer_hook = enforcer
        if enforcer is not None:
            enforcer.bind_to_priority_queue(self)

    def budget_snapshot(self) -> dict[str, Any] | None:
        if self._budget_enforcer is None:
            return None
        snap = self._budget_enforcer.snapshot()
        return {
            "budget": self._budget_enforcer.budget.to_dict(),
            **snap.to_dict(),
        }

    def trigger_retraining_loop(self) -> None:
        """ML retraining removed."""
        pass
