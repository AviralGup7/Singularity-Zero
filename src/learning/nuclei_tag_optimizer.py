"""Nuclei tag optimization based on historical feedback.

Computes precision and recall for nuclei template tags per endpoint type
and suggests optimizations to the adaptive_tags configuration to reduce
false positives and focus on high-signal templates.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from src.learning.telemetry_store import TelemetryStore

logger = logging.getLogger(__name__)


@dataclass
class TagPerformance:
    """Performance metrics for a specific nuclei tag in a given context."""

    tp: int = 0
    fp: int = 0
    total: int = 0

    @property
    def precision(self) -> float:
        """Calculate precision (TP / (TP + FP))."""
        if self.tp + self.fp == 0:
            return 1.0  # Assume clean until proven otherwise
        return self.tp / (self.tp + self.fp)

    @property
    def fp_rate(self) -> float:
        """Calculate false positive rate."""
        if self.total == 0:
            return 0.0
        return self.fp / self.total


class NucleiTagOptimizer:
    """Analyzes nuclei finding outcomes to optimize template tag selection."""

    def __init__(self, store: TelemetryStore):
        self.store = store

    def optimize_adaptive_tags(
        self,
        current_adaptive_tags: dict[str, list[str]],
        lookback_runs: int = 15,
        fp_threshold: float = 0.7,
        min_events: int = 3,
    ) -> dict[str, list[str]]:
        """
        Produce an optimized version of the adaptive_tags map.

        Args:
            current_adaptive_tags: The current mapping of endpoint categories to nuclei tags.
            lookback_runs: Number of historical runs to analyze.
            fp_threshold: FP rate above which a tag is considered noisy and demoted.
            min_events: Minimum number of findings required to make a decision.

        Returns:
            A revised adaptive_tags dictionary.
        """
        # 1. Fetch nuclei-related feedback events
        # We use a broad limit and filter for 'nuclei' plugin findings
        events = self.store.get_feedback_events(limit=2000)
        nuclei_events = [e for e in events if e.get("plugin_name") == "nuclei"]

        if not nuclei_events:
            return current_adaptive_tags

        # 2. Track performance of (endpoint_type, nuclei_tag) pairs
        # Since FeedbackEvent doesn't store the exact tags triggered, 
        # we infer them from the adaptive_tags mapping and the finding's endpoint_type.
        performance_map: dict[str, dict[str, TagPerformance]] = {}

        for event in nuclei_events:
            ep_type = event.get("endpoint_type")
            if not ep_type or ep_type not in current_adaptive_tags:
                continue

            was_tp = event.get("was_validated") and not event.get("was_false_positive")
            was_fp = event.get("was_false_positive")

            if ep_type not in performance_map:
                performance_map[ep_type] = {
                    tag: TagPerformance() for tag in current_adaptive_tags[ep_type]
                }

            # We attribute the outcome to ALL tags that were active for this endpoint type
            # This is a heuristic but effective for pruning noisy tag categories.
            for tag in current_adaptive_tags[ep_type]:
                perf = performance_map[ep_type][tag]
                perf.total += 1
                if was_tp:
                    perf.tp += 1
                if was_fp:
                    perf.fp += 1

        # 3. Generate optimized map
        optimized_tags: dict[str, list[str]] = {}

        for ep_type, tags in current_adaptive_tags.items():
            if ep_type not in performance_map:
                optimized_tags[ep_type] = list(tags)
                continue

            keep_tags = []
            for tag in tags:
                perf = performance_map[ep_type].get(tag)
                if not perf or perf.total < min_events:
                    keep_tags.append(tag)
                    continue

                if perf.fp_rate >= fp_threshold:
                    logger.warning(
                        "NucleiTagOptimizer: Demoting noisy tag [%s] for endpoint type [%s] (FP Rate: %.2f)",
                        tag,
                        ep_type,
                        perf.fp_rate,
                    )
                    # Skip adding this tag to the optimized list (demotion)
                else:
                    keep_tags.append(tag)

            # Ensure we don't leave an endpoint type with zero tags (fallback)
            if not keep_tags and tags:
                logger.info("NucleiTagOptimizer: All tags for [%s] noisy, retaining primary fallback", ep_type)
                keep_tags = [tags[0]]

            optimized_tags[ep_type] = keep_tags

        return optimized_tags
