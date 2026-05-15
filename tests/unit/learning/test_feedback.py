"""Tests for the learning feedback loop engine."""

from src.learning.feedback_loop import ExploitTarget, FeedbackLoopEngine, ScanAdaptation


class TestExploitTarget:
    def test_defaults(self):
        t = ExploitTarget(endpoint="/api/users", category="idor")
        assert t.priority == "medium"
        assert t.chain_findings == []
        assert t.validation_action == "validate"

    def test_custom_values(self):
        t = ExploitTarget(
            endpoint="/api/admin",
            category="privilege_escalation",
            priority="high",
            chain_findings=["f1", "f2"],
            validation_action="validate_chain",
        )
        assert t.priority == "high"
        assert len(t.chain_findings) == 2
        assert t.validation_action == "validate_chain"


class TestScanAdaptation:
    def test_defaults(self):
        a = ScanAdaptation()
        assert a.target_boosts == {}
        assert a.target_suppressions == {}
        assert a.plugin_enabled_overrides == {}
        assert a.plugin_intensity_overrides == {}
        assert a.payload_strategy_updates == {}
        assert a.threshold_adjustments == {}
        assert a.nuclei_template_boosts == {}
        assert a.active_exploit_queue == []

    def test_to_dict_empty(self):
        a = ScanAdaptation()
        d = a.to_dict()
        assert d["target_boosts"] == {}
        assert d["active_exploit_queue"] == []

    def test_to_dict_with_data(self):
        a = ScanAdaptation(
            target_boosts={"/api/users": 5.0},
            target_suppressions={"/api/noisy": -3.0},
            plugin_enabled_overrides={"test_plugin": True},
            plugin_intensity_overrides={"test_plugin": "aggressive"},
            payload_strategy_updates={"idor": {"identifier": 0.75}},
            threshold_adjustments={"idor": 0.02},
            nuclei_template_boosts={"idor": 3.0},
            active_exploit_queue=[
                ExploitTarget(endpoint="/api/users/1", category="idor", priority="high"),
            ],
        )
        d = a.to_dict()
        assert d["target_boosts"] == {"/api/users": 5.0}
        assert d["target_suppressions"] == {"/api/noisy": -3.0}
        assert d["plugin_enabled_overrides"] == {"test_plugin": True}
        assert d["plugin_intensity_overrides"] == {"test_plugin": "aggressive"}
        assert d["payload_strategy_updates"] == {"idor": {"identifier": 0.75}}
        assert d["threshold_adjustments"] == {"idor": 0.02}
        assert d["nuclei_template_boosts"] == {"idor": 3.0}
        assert len(d["active_exploit_queue"]) == 1
        assert d["active_exploit_queue"][0]["endpoint"] == "/api/users/1"
        assert d["active_exploit_queue"][0]["category"] == "idor"
        assert d["active_exploit_queue"][0]["priority"] == "high"


class TestFeedbackLoopEngine:
    def test_compute_adaptations_no_runs(self, store):
        engine = FeedbackLoopEngine(store)
        adaptations = engine.compute_adaptations(target="nonexistent.com")
        assert adaptations.target_boosts == {}
        assert adaptations.target_suppressions == {}

    def test_compute_adaptations_empty_target(self, store):
        engine = FeedbackLoopEngine(store)
        adaptations = engine.compute_adaptations(target="")
        assert adaptations.target_boosts == {}

    def test_target_boosts_high_validation_rate(self, store, sample_run, sample_feedback_event):
        store.record_scan_run(sample_run)
        for i in range(5):
            event = dict(sample_feedback_event)
            event["event_id"] = f"fb-val-{i}"
            event["was_validated"] = True
            event["was_false_positive"] = False
            event["feedback_weight"] = 2.5
            store.insert_feedback_event(event)

        engine = FeedbackLoopEngine(store)
        adaptations = engine.compute_adaptations(target="example.com")
        assert len(adaptations.target_boosts) >= 1

    def test_target_suppressions_high_fp_rate(self, store, sample_run, sample_feedback_event):
        store.record_scan_run(sample_run)
        for i in range(5):
            event = dict(sample_feedback_event)
            event["event_id"] = f"fb-fp-{i}"
            event["was_validated"] = False
            event["was_false_positive"] = True
            event["feedback_weight"] = 1.0
            store.insert_feedback_event(event)

        engine = FeedbackLoopEngine(store)
        adaptations = engine.compute_adaptations(target="example.com")
        assert len(adaptations.target_suppressions) >= 1
        for ep, suppression in adaptations.target_suppressions.items():
            assert suppression < 0

    def test_plugin_adaptations_high_precision(self, store, sample_run):
        store.record_scan_run(sample_run)
        for run_idx in range(3):
            run = dict(sample_run)
            run["run_id"] = f"plugin-run-{run_idx}"
            store.record_scan_run(run)
            store.record_plugin_stat(
                {
                    "stat_id": f"ps-{run_idx}",
                    "run_id": f"plugin-run-{run_idx}",
                    "plugin_name": "good_plugin",
                    "findings_produced": 10,
                    "true_positives": 9,
                    "false_positives": 1,
                    "execution_time_ms": 500.0,
                    "precision": 0.9,
                    "recall": 0.85,
                    "recorded_at": "2026-04-01T10:00:00",
                }
            )

        engine = FeedbackLoopEngine(store)
        adaptations = engine.compute_adaptations(target="example.com")
        assert "good_plugin" in adaptations.plugin_intensity_overrides
        assert adaptations.plugin_intensity_overrides["good_plugin"] == "aggressive"

    def test_plugin_adaptations_low_precision(self, store, sample_run):
        store.record_scan_run(sample_run)
        for run_idx in range(3):
            run = dict(sample_run)
            run["run_id"] = f"noisy-run-{run_idx}"
            store.record_scan_run(run)
            store.record_plugin_stat(
                {
                    "stat_id": f"ps-noisy-{run_idx}",
                    "run_id": f"noisy-run-{run_idx}",
                    "plugin_name": "noisy_plugin",
                    "findings_produced": 20,
                    "true_positives": 2,
                    "false_positives": 18,
                    "execution_time_ms": 1000.0,
                    "precision": 0.1,
                    "recall": 0.05,
                    "recorded_at": "2026-04-01T10:00:00",
                }
            )

        engine = FeedbackLoopEngine(store)
        adaptations = engine.compute_adaptations(target="example.com")
        assert "noisy_plugin" in adaptations.plugin_intensity_overrides
        assert adaptations.plugin_intensity_overrides["noisy_plugin"] == "light"

    def test_payload_strategy_updates(self, store, sample_run, sample_feedback_event):
        store.record_scan_run(sample_run)
        for i in range(5):
            event = dict(sample_feedback_event)
            event["event_id"] = f"fb-payload-{i}"
            event["was_validated"] = True
            event["was_false_positive"] = False
            event["parameter_type"] = "identifier"
            store.insert_feedback_event(event)

        engine = FeedbackLoopEngine(store)
        adaptations = engine.compute_adaptations(target="example.com")
        assert "idor" in adaptations.payload_strategy_updates
        assert "identifier" in adaptations.payload_strategy_updates["idor"]

    def test_threshold_adaptations_high_fp_rate(self, store, sample_run, sample_feedback_event):
        store.record_scan_run(sample_run)
        for i in range(5):
            event = dict(sample_feedback_event)
            event["event_id"] = f"fb-thresh-fp-{i}"
            event["was_false_positive"] = True
            store.insert_feedback_event(event)

        engine = FeedbackLoopEngine(store)
        adaptations = engine.compute_adaptations(target="example.com")
        assert "idor" in adaptations.threshold_adjustments
        assert adaptations.threshold_adjustments["idor"] > 0

    def test_threshold_adaptations_low_fp_rate(self, store, sample_run, sample_feedback_event):
        store.record_scan_run(sample_run)
        for i in range(8):
            event = dict(sample_feedback_event)
            event["event_id"] = f"fb-thresh-low-{i}"
            event["was_false_positive"] = False
            store.insert_feedback_event(event)

        engine = FeedbackLoopEngine(store)
        adaptations = engine.compute_adaptations(target="example.com")
        assert "idor" in adaptations.threshold_adjustments
        assert adaptations.threshold_adjustments["idor"] < 0

    def test_nuclei_template_boosts(self, store, sample_run, sample_feedback_event):
        store.record_scan_run(sample_run)
        for i in range(3):
            event = dict(sample_feedback_event)
            event["event_id"] = f"fb-nuclei-{i}"
            event["was_validated"] = True
            event["was_false_positive"] = False
            event["feedback_weight"] = 2.0
            store.insert_feedback_event(event)

        engine = FeedbackLoopEngine(store)
        adaptations = engine.compute_adaptations(target="example.com")
        assert "idor" in adaptations.nuclei_template_boosts

    def test_active_exploit_queue(self, store, sample_run, sample_finding):
        store.record_scan_run(sample_run)
        finding = dict(sample_finding)
        finding["confidence"] = 0.9
        finding["lifecycle_state"] = "DETECTED"
        finding["category"] = "xss"
        store.record_finding(finding)

        engine = FeedbackLoopEngine(store)
        adaptations = engine.compute_adaptations(target="example.com")
        assert len(adaptations.active_exploit_queue) >= 1
        assert adaptations.active_exploit_queue[0].priority == "high"

    def test_active_exploit_queue_medium_priority(self, store, sample_run, sample_finding):
        store.record_scan_run(sample_run)
        finding = dict(sample_finding)
        finding["confidence"] = 0.75
        finding["lifecycle_state"] = "DETECTED"
        finding["category"] = "ssrf"
        store.record_finding(finding)

        engine = FeedbackLoopEngine(store)
        adaptations = engine.compute_adaptations(target="example.com")
        assert len(adaptations.active_exploit_queue) >= 1
        assert adaptations.active_exploit_queue[0].priority == "medium"

    def test_active_exploit_queue_dedup(self, store, sample_run, sample_finding):
        store.record_scan_run(sample_run)
        for i in range(3):
            finding = dict(sample_finding)
            finding["finding_id"] = f"dedup-{i}"
            finding["confidence"] = 0.8
            finding["lifecycle_state"] = "DETECTED"
            finding["category"] = "idor"
            store.record_finding(finding)

        engine = FeedbackLoopEngine(store)
        adaptations = engine.compute_adaptations(target="example.com")
        endpoints = [t.endpoint for t in adaptations.active_exploit_queue]
        assert len(endpoints) == len(set(endpoints))

    def test_active_exploit_queue_limit_20(self, store, sample_run, sample_finding):
        store.record_scan_run(sample_run)
        for i in range(30):
            finding = dict(sample_finding)
            finding["finding_id"] = f"limit-{i}"
            finding["url"] = f"https://api.example.com/api/v1/item/{i}"
            finding["confidence"] = 0.8
            finding["lifecycle_state"] = "DETECTED"
            finding["category"] = "idor"
            store.record_finding(finding)

        engine = FeedbackLoopEngine(store)
        adaptations = engine.compute_adaptations(target="example.com")
        assert len(adaptations.active_exploit_queue) <= 20

    def test_active_exploit_queue_only_vuln_categories(self, store, sample_run, sample_finding):
        store.record_scan_run(sample_run)
        finding = dict(sample_finding)
        finding["confidence"] = 0.8
        finding["lifecycle_state"] = "DETECTED"
        finding["category"] = "anomaly"
        store.record_finding(finding)

        engine = FeedbackLoopEngine(store)
        adaptations = engine.compute_adaptations(target="example.com")
        categories = [t.category for t in adaptations.active_exploit_queue]
        assert "anomaly" not in categories

    def test_skip_validated_findings(self, store, sample_run, sample_finding):
        store.record_scan_run(sample_run)
        finding = dict(sample_finding)
        finding["confidence"] = 0.9
        finding["lifecycle_state"] = "VALIDATED"
        finding["category"] = "xss"
        store.record_finding(finding)

        engine = FeedbackLoopEngine(store)
        adaptations = engine.compute_adaptations(target="example.com")
        for t in adaptations.active_exploit_queue:
            assert t.category != "xss" or t.endpoint != finding["url"]

    def test_mode_deep(self, store, sample_run):
        store.record_scan_run(sample_run)
        engine = FeedbackLoopEngine(store)
        adaptations = engine.compute_adaptations(target="example.com", mode="deep")
        assert isinstance(adaptations, ScanAdaptation)

    def test_mode_fast(self, store, sample_run):
        store.record_scan_run(sample_run)
        engine = FeedbackLoopEngine(store)
        adaptations = engine.compute_adaptations(target="example.com", mode="fast")
        assert isinstance(adaptations, ScanAdaptation)

    def test_lookback_runs(self, store, sample_run):
        for i in range(15):
            run = dict(sample_run)
            run["run_id"] = f"lookback-{i:03d}"
            store.record_scan_run(run)

        engine = FeedbackLoopEngine(store)
        adaptations = engine.compute_adaptations(target="example.com", lookback_runs=5)
        assert isinstance(adaptations, ScanAdaptation)

    def test_endpoint_stats_empty_endpoint(self, store, sample_run, sample_feedback_event):
        store.record_scan_run(sample_run)
        event = dict(sample_feedback_event)
        event["event_id"] = "fb-empty-ep"
        event["target_endpoint"] = ""
        store.insert_feedback_event(event)

        engine = FeedbackLoopEngine(store)
        adaptations = engine.compute_adaptations(target="example.com")
        assert isinstance(adaptations, ScanAdaptation)

    def test_plugin_stats_empty_name(self, store, sample_run):
        store.record_scan_run(sample_run)
        store.record_plugin_stat(
            {
                "stat_id": "ps-empty",
                "run_id": "test-run-001",
                "plugin_name": "",
                "findings_produced": 5,
                "true_positives": 3,
                "false_positives": 2,
                "execution_time_ms": 200.0,
                "precision": 0.6,
                "recall": 0.5,
                "recorded_at": "2026-04-01T10:00:00",
            }
        )

        engine = FeedbackLoopEngine(store)
        adaptations = engine.compute_adaptations(target="example.com")
        assert "" not in adaptations.plugin_enabled_overrides
        assert "" not in adaptations.plugin_intensity_overrides

    def test_payload_stats_insufficient_data(self, store, sample_run, sample_feedback_event):
        store.record_scan_run(sample_run)
        event = dict(sample_feedback_event)
        event["event_id"] = "fb-payload-low"
        event["parameter_type"] = "token"
        store.insert_feedback_event(event)

        engine = FeedbackLoopEngine(store)
        adaptations = engine.compute_adaptations(target="example.com")
        assert (
            "idor" not in adaptations.payload_strategy_updates
            or "token" not in adaptations.payload_strategy_updates.get("idor", {})
        )

    def test_threshold_stats_insufficient_data(self, store, sample_run, sample_feedback_event):
        store.record_scan_run(sample_run)
        event = dict(sample_feedback_event)
        event["event_id"] = "fb-thresh-low"
        store.insert_feedback_event(event)

        engine = FeedbackLoopEngine(store)
        adaptations = engine.compute_adaptations(target="example.com")
        assert "idor" not in adaptations.threshold_adjustments

    def test_nuclei_boost_below_threshold(self, store, sample_run, sample_feedback_event):
        store.record_scan_run(sample_run)
        event = dict(sample_feedback_event)
        event["event_id"] = "fb-nuclei-low"
        event["was_validated"] = True
        event["was_false_positive"] = False
        event["feedback_weight"] = 0.5
        store.insert_feedback_event(event)

        engine = FeedbackLoopEngine(store)
        adaptations = engine.compute_adaptations(target="example.com")
        assert "idor" not in adaptations.nuclei_template_boosts

    def test_nuclei_boost_capped_at_5(self, store, sample_run, sample_feedback_event):
        store.record_scan_run(sample_run)
        for i in range(10):
            event = dict(sample_feedback_event)
            event["event_id"] = f"fb-nuclei-cap-{i}"
            event["was_validated"] = True
            event["was_false_positive"] = False
            event["feedback_weight"] = 3.0
            store.insert_feedback_event(event)

        engine = FeedbackLoopEngine(store)
        adaptations = engine.compute_adaptations(target="example.com")
        if "idor" in adaptations.nuclei_template_boosts:
            assert adaptations.nuclei_template_boosts["idor"] <= 5.0

    def test_target_boost_capped_at_10(self, store, sample_run, sample_feedback_event):
        store.record_scan_run(sample_run)
        for i in range(20):
            event = dict(sample_feedback_event)
            event["event_id"] = f"fb-boost-cap-{i}"
            event["was_validated"] = True
            event["was_false_positive"] = False
            event["feedback_weight"] = 5.0
            store.insert_feedback_event(event)

        engine = FeedbackLoopEngine(store)
        adaptations = engine.compute_adaptations(target="example.com")
        for ep, boost in adaptations.target_boosts.items():
            assert boost <= 10.0

    def test_target_suppressions_exist(self, store, sample_run, sample_feedback_event):
        store.record_scan_run(sample_run)
        for i in range(5):
            event = dict(sample_feedback_event)
            event["event_id"] = f"fb-sup-cap-{i}"
            event["was_validated"] = False
            event["was_false_positive"] = True
            event["feedback_weight"] = 5.0
            store.insert_feedback_event(event)

        engine = FeedbackLoopEngine(store)
        adaptations = engine.compute_adaptations(target="example.com")
        for ep, supp in adaptations.target_suppressions.items():
            assert supp < 0

    def test_plugin_insufficient_runs(self, store, sample_run):
        store.record_scan_run(sample_run)
        store.record_plugin_stat(
            {
                "stat_id": "ps-one-run",
                "run_id": "test-run-001",
                "plugin_name": "single_run_plugin",
                "findings_produced": 10,
                "true_positives": 8,
                "false_positives": 2,
                "execution_time_ms": 300.0,
                "precision": 0.8,
                "recall": 0.7,
                "recorded_at": "2026-04-01T10:00:00",
            }
        )

        engine = FeedbackLoopEngine(store)
        adaptations = engine.compute_adaptations(target="example.com")
        assert "single_run_plugin" not in adaptations.plugin_intensity_overrides

    def test_feedback_weight_used_in_target_stats(self, store, sample_run, sample_feedback_event):
        store.record_scan_run(sample_run)
        event = dict(sample_feedback_event)
        event["event_id"] = "fb-weight-test"
        event["was_validated"] = True
        event["was_false_positive"] = False
        event["feedback_weight"] = 3.0
        store.insert_feedback_event(event)

        engine = FeedbackLoopEngine(store)
        adaptations = engine.compute_adaptations(target="example.com")
        assert isinstance(adaptations, ScanAdaptation)

    def test_multiple_categories_threshold(self, store, sample_run, sample_feedback_event):
        store.record_scan_run(sample_run)
        for i in range(5):
            event = dict(sample_feedback_event)
            event["event_id"] = f"fb-multi-cat-{i}"
            event["finding_category"] = "xss"
            event["was_false_positive"] = True
            store.insert_feedback_event(event)

        engine = FeedbackLoopEngine(store)
        adaptations = engine.compute_adaptations(target="example.com")
        assert "xss" in adaptations.threshold_adjustments
