"""Unit tests for NucleiTagOptimizer.

Tests use a real TelemetryStore backed by a temporary SQLite database so
that _get_recent_feedback exercises the actual repository layer.
"""

from __future__ import annotations

import uuid

import pytest

from src.learning.nuclei_tag_optimizer import NucleiTagOptimizer
from src.learning.telemetry_store import TelemetryStore

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_event(
    db_run_id: str,
    *,
    plugin_name: str = "nuclei:vuln_tag",
    endpoint_type: str = "api",
    was_validated: bool = False,
    was_false_positive: bool = False,
    finding_confidence: float = 0.5,
    **extra,
) -> dict:
    """Build a single feedback-event dict ready for ``insert_feedback_event``.

    ``event_id`` is always a UUID so that multiple independent calls never
    produce the same PRIMARY KEY regardless of calling context.
    Any additional keyword arguments are merged into the returned dict so
    callers can set ``finding_category``, ``tech_stack``, etc. without those
    fields needing to be explicit parameters here.
    """
    return {
        "event_id": f"ev-{uuid.uuid4().hex[:12]}",
        "run_id": db_run_id,
        "timestamp": "2026-05-22T05:00:00",
        "target_host": "target.example.com",
        "target_endpoint": f"https://target.example.com/{endpoint_type}/endpoint",
        "finding_category": "generic_category",
        "finding_severity": "medium",
        "finding_confidence": finding_confidence,
        "finding_decision": "MEDIUM",
        "plugin_name": plugin_name,
        "parameter_name": "id",
        "parameter_type": "identifier",
        "was_validated": was_validated,
        "was_false_positive": was_false_positive,
        "validation_method": None,
        "response_delta_score": None,
        "endpoint_type": endpoint_type,
        "tech_stack": "python,flask",
        "scan_mode": "deep",
        "feedback_weight": 1.0,
        **extra,
    }


def _inject_scan_run(store: TelemetryStore, run_id: str) -> None:
    """Record a minimal scan run so _get_recent_feedback can find it.

    Uses a stable, run_id-derived per-minute offset so that multiple calls
    in the same test always produce distinct ``start_time`` values and avoid
    INSERT OR REPLACE silently overwriting an earlier run.
    """
    import hashlib

    # Map run_id → a deterministic minute slot in [00, 59]
    digest = hashlib.sha256(run_id.encode()).hexdigest()
    minute = int(digest[:2], 16) % 60
    ts_start = f"2026-05-22T05:{minute:02d}:00"
    ts_end = f"2026-05-22T05:{minute:02d}:30"
    store.record_scan_run(
        {
            "run_id": run_id,
            "target_name": "example.com",
            "mode": "deep",
            "start_time": ts_start,
            "end_time": ts_end,
            "status": "completed",
            "total_urls": 0,
            "total_endpoints": 0,
            "total_findings": 0,
            "validated_findings": 0,
            "false_positives": 0,
            "scan_duration_sec": 30.0,
            "config_hash": "",
            "feedback_applied": False,
        }
    )


def _make_optimizer_and_tags(store: TelemetryStore):
    """Seed *store* and return ``(optimizer, adaptive_tags)``.

    adaptive_tags uses ``list[dict]`` entries so that every tag carries an
    explicit ``intensity_multiplier`` (the Phase 5.1 contract).

    Tag layout (all events use ``plugin_name = "nuclei:<tag>"`` so the
    ``:``-split extracts the correct tag key):

      ``"boosting_env"``
          ``good_tag``       – 8 TP, 2 FP → F1 = 0.80  → BOOST
          ``neutral_tag``    – 0 events                → UNTOUCHED

      ``"noisy_env"``
          ``bad_tag``        – 0 TP, 8 FP → F1 = 0.0   → DEMOTE
          ``neutral_tag``    – 0 events                → UNTOUCHED
    """
    DB_RUN = "test-run-001"
    _inject_scan_run(store, DB_RUN)

    def _e(env: str, tag: str, **kw) -> dict:
        """Produce one nuclei feedback event for *env* / *tag*.

        ``plugin_name`` is ``"nuclei:<tag>"`` — ``optimize_adaptive_tags``
        extracts the actual tag key via ``plugin_name.split(":")[0]``, so
        this format guarantees the extracted key is the tag string that also
        appears in ``adaptive_tags[env]``.
        """
        return _make_event(
            DB_RUN,
            plugin_name=f"nuclei:{tag}",
            endpoint_type=env,
            finding_category=tag,
            **kw,
        )

    good_tag_events = [
        _e(
            "boosting_env",
            "good_tag",
            was_validated=True,
            was_false_positive=False,
            finding_confidence=0.9,
        )
        for _ in range(8)
    ] + [
        _e(
            "boosting_env",
            "good_tag",
            was_validated=False,
            was_false_positive=True,
            finding_confidence=0.3,
        )
        for _ in range(2)
    ]

    bad_tag_events = [
        _e(
            "noisy_env",
            "bad_tag",
            was_validated=False,
            was_false_positive=True,
            finding_confidence=0.3,
        )
        for _ in range(8)
    ]

    all_events = good_tag_events + bad_tag_events
    for ev in all_events:
        store.insert_feedback_event(ev)

    optimizer = NucleiTagOptimizer(store, lookback_runs=1)

    adaptive_tags: dict[str, list[dict]] = {
        "boosting_env": [
            {"tag": "good_tag", "intensity_multiplier": 1.0},
            {"tag": "neutral_tag", "intensity_multiplier": 1.0},
        ],
        "noisy_env": [
            {"tag": "bad_tag", "intensity_multiplier": 1.0},
            {"tag": "neutral_tag", "intensity_multiplier": 1.0},
        ],
    }
    return optimizer, adaptive_tags


# ---------------------------------------------------------------------------
# Tests – F1-based multiplier adjustment
# ---------------------------------------------------------------------------


class TestOptimizeAdaptiveTagsF1BasedAdjustment:
    """End-to-end tests using a real TelemetryStore (seeded in-package)."""

    @pytest.fixture
    def store(self, tmp_db_path):
        """Provide an initialized TelemetryStore backed by a temp file."""
        s = TelemetryStore(tmp_db_path)
        s.initialize()
        yield s
        s.close()

    @pytest.fixture
    def fixtures(self, store):
        return _make_optimizer_and_tags(store)

    # -- demotion ----------------------------------------------------------

    def test_demoted_tag_multiplier_halved(self, fixtures):
        """F1 = 0 << 0.3 → intensity_multiplier must be exactly half the original."""
        optimizer, adaptive_tags = fixtures
        result = optimizer.optimize_adaptive_tags(adaptive_tags, lookback_runs=1)

        noisy_env = result["noisy_env"]
        bad_entry = next(e for e in noisy_env if isinstance(e, dict) and e["tag"] == "bad_tag")
        assert bad_entry["intensity_multiplier"] == pytest.approx(0.5), (
            f"Expected demoted multiplier 0.5, got {bad_entry['intensity_multiplier']}"
        )

    # -- boosting ----------------------------------------------------------

    def test_boosted_tag_multiplier_increased_25pct(self, fixtures):
        """F1 = 0.80 > 0.7 → intensity_multiplier must be ×1.25 the original."""
        optimizer, adaptive_tags = fixtures
        result = optimizer.optimize_adaptive_tags(adaptive_tags, lookback_runs=1)

        boost_env = result["boosting_env"]
        good_entry = next(e for e in boost_env if isinstance(e, dict) and e["tag"] == "good_tag")
        assert good_entry["intensity_multiplier"] == pytest.approx(1.25), (
            f"Expected boosted multiplier 1.25, got {good_entry['intensity_multiplier']}"
        )

    # -- untouched ---------------------------------------------------------

    def test_untouched_neutral_tags_preserved(self, fixtures):
        """Tags never seen in any feedback event must keep multiplier 1.0."""
        optimizer, adaptive_tags = fixtures
        result = optimizer.optimize_adaptive_tags(adaptive_tags, lookback_runs=1)

        for env in ("boosting_env", "noisy_env"):
            entries = result[env]
            neutral = next(e for e in entries if isinstance(e, dict) and e["tag"] == "neutral_tag")
            assert neutral["intensity_multiplier"] == pytest.approx(
                1.0,
            ), f"neutral_tag in {env} should be untouched (got {neutral['intensity_multiplier']})"

    # -- identity on no data ----------------------------------------------

    def test_no_feedback_returns_shallow_copy(self, store):
        """With zero feedback events the original dict must be returned as-is."""
        _inject_scan_run(store, "empty-run-001")

        optimizer = NucleiTagOptimizer(store, lookback_runs=1)
        tags = {"web": [{"tag": "any", "intensity_multiplier": 1.5}]}
        result = optimizer.optimize_adaptive_tags(tags, lookback_runs=1)
        assert result == tags

    def test_returns_new_dict_even_when_unchanged(self, store):
        """optimize_adaptive_tags always returns a new dict to satisfy caller diffing."""
        _inject_scan_run(store, "same-run-001")
        tags: dict[str, list[str]] = {"web": ["exposure"]}

        optimizer = NucleiTagOptimizer(store, lookback_runs=1)
        result = optimizer.optimize_adaptive_tags(tags, lookback_runs=1)
        assert result is not tags
        assert result == tags


# ---------------------------------------------------------------------------
# Tests – _compute_f1_ratio
# ---------------------------------------------------------------------------


class TestComputeF1Ratio:
    """Pure unit tests for _compute_f1_ratio (no DB required)."""

    def test_no_events_default_f1(self):
        self._assert_ratio([], "x", f1=1.0, count=0)

    def test_all_tp_one_hundred_pct(self):
        # "nuclei:vuln_tag" → ev_tag = "vuln_tag"
        events = [_make_event("r", was_validated=True, was_false_positive=False)] * 5
        self._assert_ratio(events, "vuln_tag", f1=1.0, count=5)

    def test_all_fp_zero_f1(self):
        events = [_make_event("r", was_validated=False, was_false_positive=True)] * 5
        self._assert_ratio(events, "vuln_tag", f1=0.0 / 5, count=5)

    def test_mixed_tp_fp(self):
        # 8 TP + 2 FP → F1 = 8 / 10 = 0.80
        events = [_make_event("r", was_validated=True, was_false_positive=False)] * 8 + [
            _make_event("r", was_validated=False, was_false_positive=True)
        ] * 2
        self._assert_ratio(events, "vuln_tag", f1=0.8, count=10)

    def test_mixed_tp_fn(self):
        # 5 TP + 3 FN (not validated, not FP) → F1 = 5 / 8 = 0.625
        events = [_make_event("r", was_validated=True, was_false_positive=False)] * 5 + [
            _make_event("r", was_validated=False, was_false_positive=False)
        ] * 3
        self._assert_ratio(events, "vuln_tag", f1=5 / 8, count=8)

    def test_different_tag_excluded(self):
        """Events with a tag that does not equal the query tag are ignored."""
        events = [
            _make_event(
                "r",
                plugin_name="nuclei:sqli",
                was_validated=True,
                was_false_positive=False,
            ),
            _make_event(
                "r",
                plugin_name="nuclei:sqli",
                was_validated=False,
                was_false_positive=True,
            ),
        ]
        # Tag is "sqli" from those events; we query for "lfi" → 0 matches
        self._assert_ratio(events, "lfi", f1=1.0, count=0)

    @staticmethod
    def _assert_ratio(events: list[dict], tag: str, *, f1: float, count: int) -> None:
        optimizer = NucleiTagOptimizer.__new__(NucleiTagOptimizer)
        got_f1, got_count = optimizer._compute_f1_ratio(events, tag)
        assert pytest.approx(got_f1, abs=1e-9) == f1, f"Expected F1={f1}, got {got_f1}"
        assert got_count == count


# ---------------------------------------------------------------------------
# Tests – _get_recent_feedback
# ---------------------------------------------------------------------------


class TestGetRecentFeedback:
    """Integration tests for _get_recent_feedback."""

    def test_returns_events_for_known_run(self, store):
        """Events belonging to a recorded scan run are returned."""
        run_id = "feedback-run-200"
        _inject_scan_run(store, run_id)

        events = [_make_event(run_id, endpoint_type="api") for _ in range(3)]
        for ev in events:
            store.insert_feedback_event(ev)

        optimizer = NucleiTagOptimizer(store, lookback_runs=2)
        result = optimizer._get_recent_feedback(lookback_runs=1)
        assert len(result) >= 3

    def test_empty_store_no_scan_runs(self, tmp_db_path):
        """Store with no scan runs must not raise; falls back to all events."""
        store = TelemetryStore(tmp_db_path)
        store.initialize()
        try:
            optimizer = NucleiTagOptimizer(store, lookback_runs=3)
            result = optimizer._get_recent_feedback(lookback_runs=3)
            assert isinstance(result, list)
        finally:
            store.close()

    def test_multiple_runs_aggregated(self, store):
        """Events from all lookback_runs runs are aggregated."""
        _inject_scan_run(store, "run-a")
        _inject_scan_run(store, "run-b")
        for rid in ("run-a", "run-b"):
            for i in range(2):
                store.insert_feedback_event(_make_event(rid, endpoint_type="api"))

        optimizer = NucleiTagOptimizer(store, lookback_runs=2)
        result = optimizer._get_recent_feedback(lookback_runs=2)
        assert len(result) == 4
