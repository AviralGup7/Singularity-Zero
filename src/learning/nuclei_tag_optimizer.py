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
class TagEntry:
    """A single tag entry inside an adaptive_tags value list."""

    name: str
    intensity_multiplier: float = 1.0


@dataclass
class TagPerformance:
    """Performance metrics for a specific nuclei tag in a given context."""

    tp: int = 0
    fp: int = 0
    fn: int = 0
    total: int = 0

    @property
    def precision(self) -> float:
        """TP / (TP + FP). Returns 1.0 when no evidence exists."""
        if self.tp + self.fp == 0:
            return 1.0
        return self.tp / (self.tp + self.fp)

    @property
    def recall(self) -> float:
        """TP / (TP + FN). Returns 1.0 when no evidence exists."""
        if self.tp + self.fn == 0:
            return 1.0
        return self.tp / (self.tp + self.fn)

    @property
    def f1(self) -> float:
        """F1 = TP / (TP + FP + FN)."""
        denom = self.tp + self.fp + self.fn
        if denom == 0:
            return 1.0
        return self.tp / denom


class NucleiTagOptimizer:
    """Analyzes nuclei finding outcomes to optimise template tag selection.

    Reads feedback events from the last ``lookback_runs`` scan runs and
    adjusts ``intensity_multiplier`` values inside ``current_adaptive_tags``
    based on each tag's F1 score:

    * F1 < 0.3  – demote  (multiplier × 0.5)
    * F1 > 0.7  – boost   (multiplier × 1.25)
    * unseen    – untouched
    """

    def __init__(self, store: TelemetryStore, lookback_runs: int = 5) -> None:
        self.store = store
        self.lookback_runs = lookback_runs

    def optimize_adaptive_tags(
        self,
        current_adaptive_tags: dict[str, Any],
        lookback_runs: int = 5,
    ) -> dict[str, Any]:
        """Produce an optimised copy of *current_adaptive_tags*.

        Args:
            current_adaptive_tags: Mapping of endpoint category to a list of
                tag entries.  Each entry is either a plain ``str`` (treated as
                a tag name with multiplier 1.0) or a ``dict`` with at least a
                ``\"tag\"`` key.

            lookback_runs: Number of recent scan runs to include in the
                analysis.

        Returns:
            A **new** ``dict`` with the same top-level keys.  Per-tag lists are
            reconstructed with adjusted ``intensity_multiplier`` values where
            feedback was observed.  Tags that were never seen in feedback are
            left unchanged.
        """
        feedback_events = self._get_recent_feedback(lookback_runs)

        # Filter for 'nuclei:*' plugin findings (tag key = value before the colon)
        nuclei_filtered = [
            e for e in feedback_events
            if e.get("plugin_name", "").startswith("nuclei")
        ]

        if not nuclei_filtered:
            # No data → return a shallow copy (correctness contract is
            # "new dict" so callers can diff on identity).
            return dict(current_adaptive_tags)

        # Build a lookup: (endpoint_type, tag_key) -> TagPerformance
        perf_map: dict[tuple[str, str], TagPerformance] = {}

        for event in nuclei_filtered:
            ep_type: str = event.get("endpoint_type") or ""
            raw_tag: str = event.get("plugin_name") or ""

            # Extract the tag key.
            # Primary: last token after ':'  → handles "nuclei:<actual_tag>".
            # Fallback: first token before '_' → handles "bad_tag_subtype".
            tag_key = raw_tag.split(":")[-1]
            if not tag_key:
                tag_key = raw_tag.split("_")[0]

            if not ep_type or not tag_key:
                continue

            was_validated = bool(event.get("was_validated"))
            was_fp = bool(event.get("was_false_positive"))

            is_tp = was_validated and not was_fp
            is_fp = was_fp
            # FN: was_not_validated AND not_false_positive (missed detection)
            is_fn = not was_validated and not was_fp

            key = (ep_type, tag_key)
            if key not in perf_map:
                perf_map[key] = TagPerformance()
            perf = perf_map[key]
            perf.total += 1
            if is_tp:
                perf.tp += 1
            if is_fp:
                perf.fp += 1
            if is_fn:
                perf.fn += 1

        # Build the optimised output
        result: dict[str, Any] = {}
        for ep_cat, raw_entries in current_adaptive_tags.items():
            optimised_entries: list[TagEntry] = []
            for raw_entry in raw_entries:
                entry = self._parse_tag_entry(raw_entry)
                perf_key = (ep_cat, entry.name)
                if perf_key in perf_map:
                    perf = perf_map[perf_key]
                    f1 = perf.f1
                    if f1 < 0.3:
                        entry.intensity_multiplier = round(entry.intensity_multiplier * 0.5, 4)
                    elif f1 > 0.7:
                        entry.intensity_multiplier = round(entry.intensity_multiplier * 1.25, 4)
                    # F1 in [0.3, 0.7]: leave multiplier unchanged
                # Tags never seen in feedback → entry left at original multiplier

                optimised_entries.append(TagEntry(entry.name, entry.intensity_multiplier))

            if all(isinstance(e, str) for e in raw_entries):
                # Caller passed plain str tags → preserve that shape.
                output_value: list[Any] = [e.name for e in optimised_entries]
            else:
                # Caller passed structured dict entries.
                output_value = [
                    {"tag": e.name, "intensity_multiplier": e.intensity_multiplier}
                    for e in optimised_entries
                ]
            result[ep_cat] = output_value

        return result

    @staticmethod
    def _parse_tag_entry(raw: Any) -> TagEntry:
        """Normalise a raw tag entry (str or dict) to a ``TagEntry``."""
        if isinstance(raw, str):
            return TagEntry(name=raw, intensity_multiplier=1.0)
        if isinstance(raw, dict):
            return TagEntry(
                name=str(raw.get("tag") or raw.get("name") or ""),
                intensity_multiplier=float(raw.get("intensity_multiplier") or raw.get("multiplier") or 1.0),
            )
        return TagEntry(name=str(raw))

    def _get_recent_feedback(self, lookback_runs: int) -> list[dict]:
        """Return feedback events from the last *lookback_runs* scan runs.

        Falls back to all events if the scan_runs table is empty.
        """
        try:
            recent_runs = self.store.get_recent_runs(limit=lookback_runs)
            if not recent_runs:
                return self.store.get_feedback_events(limit=2000)

            run_ids = [r["run_id"] for r in recent_runs if r.get("run_id")]
            all_events: list[dict] = []
            for rid in run_ids:
                all_events.extend(self.store.get_feedback_events_for_run(rid))
            return all_events
        except Exception:  # noqa: BLE001
            logger.warning(
                "_get_recent_feedback: failed to read scan runs, "
                "falling back to all events",
                exc_info=True,
            )
            return self.store.get_feedback_events(limit=2000)

    def _compute_f1_ratio(
        self,
        events: list[dict],
        tag: str,
    ) -> tuple[float, int]:
        """Compute F1 ratio and event count for *tag* across *events*.

        Only events whose ``plugin_name`` (after splitting on ``:``) match
        *tag* are included.

        Args:
            events: Raw feedback-event dicts.
            tag:    The tag key to measure.

        Returns:
            ``(f1_score, event_count)``
        """
        tp = fp = fn = 0
        for ev in events:
            raw_plugin: str = ev.get("plugin_name") or ""
            # Use the last ':' segment as the tag key ("nuclei:<actual_tag>")
            ev_tag = raw_plugin.split(":")[-1]
            if ev_tag != tag:
                continue

            was_validated = bool(ev.get("was_validated"))
            was_fp = bool(ev.get("was_false_positive"))

            if was_validated and not was_fp:
                tp += 1
            elif was_fp:
                fp += 1
            else:
                fn += 1

        total = tp + fp + fn
        f1 = tp / total if total > 0 else 1.0
        return f1, total
