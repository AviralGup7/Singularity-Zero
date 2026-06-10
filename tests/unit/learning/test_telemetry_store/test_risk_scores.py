class TestTelemetryStoreRiskScores:
    """Tests for risk score operations."""

    def test_upsert_and_get_risk_scores(self, store, sample_run):
        store.record_scan_run(sample_run)
        score = {
            "score_id": "rs-001",
            "run_id": "test-run-001",
            "endpoint": "/api/users",
            "host": "api.example.com",
            "category": "idor",
            "prior_risk": 0.3,
            "likelihood_ratio": 2.0,
            "recency_weight": 0.9,
            "context_modifier": 1.2,
            "exploration_bonus": 0.1,
            "correlation_amp": 1.1,
            "final_score": 0.78,
            "score_components": '{"prior_risk": 0.3}',
            "computed_at": "2026-04-01T10:15:00",
        }
        store.upsert_risk_score(score)
        scores = store.get_risk_scores_for_run("test-run-001")
        assert len(scores) == 1
        assert scores[0]["final_score"] == 0.78

    def test_upsert_risk_score_with_dict_components(self, store, sample_run):
        store.record_scan_run(sample_run)
        score = {
            "score_id": "rs-dict-001",
            "run_id": "test-run-001",
            "endpoint": "/api/admin",
            "host": "api.example.com",
            "category": "privilege_escalation",
            "prior_risk": 0.5,
            "likelihood_ratio": 1.5,
            "recency_weight": 0.8,
            "context_modifier": 1.0,
            "exploration_bonus": 0.05,
            "correlation_amp": 1.0,
            "final_score": 0.6,
            "score_components": {"prior_risk": 0.5, "likelihood_ratio": 1.5},
            "computed_at": "2026-04-01T10:15:00",
        }
        store.upsert_risk_score(score)
        scores = store.get_risk_scores_for_run("test-run-001")
        assert len(scores) == 1

    def test_get_risk_scores_empty(self, store, sample_run):
        store.record_scan_run(sample_run)
        scores = store.get_risk_scores_for_run("test-run-001")
        assert len(scores) == 0
