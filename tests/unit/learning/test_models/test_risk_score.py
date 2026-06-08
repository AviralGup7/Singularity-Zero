from src.learning.models.risk_score import RiskScore


class TestRiskScore:
    """Tests for RiskScore model."""

    def test_compute(self):
        result = RiskScore.compute(
            run_id="run-001",
            endpoint="/api/users",
            host="api.example.com",
            category="idor",
            prior_risk=0.3,
            likelihood_ratio=2.0,
            recency_weight=0.9,
            context_modifier=1.2,
            exploration_bonus=0.1,
            correlation_amplifier=1.1,
        )
        assert abs(result.final_score - 0.78408) < 0.001
        assert result.score_id.startswith("rs-")

    def test_compute_score_id_deterministic(self):
        r1 = RiskScore.compute(
            run_id="run-001",
            endpoint="/api/users",
            host="api.example.com",
            category="idor",
            prior_risk=0.3,
            likelihood_ratio=2.0,
            recency_weight=0.9,
            context_modifier=1.2,
            exploration_bonus=0.1,
            correlation_amplifier=1.1,
        )
        r2 = RiskScore.compute(
            run_id="run-001",
            endpoint="/api/users",
            host="api.example.com",
            category="idor",
            prior_risk=0.3,
            likelihood_ratio=2.0,
            recency_weight=0.9,
            context_modifier=1.2,
            exploration_bonus=0.1,
            correlation_amplifier=1.1,
        )
        assert r1.score_id == r2.score_id

    def test_compute_components(self):
        result = RiskScore.compute(
            run_id="run-001",
            endpoint="/api/users",
            host="api.example.com",
            category="idor",
            prior_risk=0.3,
            likelihood_ratio=2.0,
            recency_weight=0.9,
            context_modifier=1.2,
            exploration_bonus=0.1,
            correlation_amplifier=1.1,
        )
        assert "prior_risk" in result.score_components
        assert result.score_components["prior_risk"] == 0.3
        assert result.score_components["likelihood_ratio"] == 2.0

    def test_compute_zero_prior(self):
        result = RiskScore.compute(
            run_id="run-001",
            endpoint="/api/users",
            host="api.example.com",
            category="idor",
            prior_risk=0.0,
            likelihood_ratio=2.0,
            recency_weight=0.9,
            context_modifier=1.2,
            exploration_bonus=0.1,
            correlation_amplifier=1.1,
        )
        assert result.final_score == 0.0

    def test_compute_high_values(self):
        result = RiskScore.compute(
            run_id="run-001",
            endpoint="/api/admin",
            host="api.example.com",
            category="privilege_escalation",
            prior_risk=0.9,
            likelihood_ratio=3.0,
            recency_weight=1.0,
            context_modifier=2.0,
            exploration_bonus=0.5,
            correlation_amplifier=1.5,
        )
        assert result.final_score > 0.9
