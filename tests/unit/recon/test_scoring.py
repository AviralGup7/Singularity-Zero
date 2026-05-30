from unittest.mock import patch

from src.recon.scoring import (
    compute_aggregate_risk_score,
    compute_historical_score,
    flow_score,
    infer_target_profile,
    query_parameter_names,
    rank_urls,
    resolve_priority_limit,
    score_context_bonus,
    score_mode_bonus,
    score_url,
    score_url_precomputed,
)


class TestScoring:
    def test_infer_target_profile(self):
        urls = [
            "https://example.com/api/v1/users",
            "https://example.com/api/v1/login",
            "https://example.com/auth/session",
            "https://example.com/upload/file.png",
            "https://example.com/page?id=1",
            "https://example.com/page?id=2",
            "https://example.com/page?id=3",
            "https://example.com/page?id=4",
            "https://example.com/page?id=5",
            "https://example.com/page?id=6",
        ]
        profile = infer_target_profile(urls)
        assert profile["api_heavy"] is True  # 2/10 = 0.2
        assert profile["auth_heavy"] is True  # 2/10 = 0.2 >= 0.12
        assert profile["parameter_heavy"] is True  # 6/10 = 0.6 >= 0.25
        assert profile["file_heavy"] is True  # 1/10 = 0.1 >= 0.08
        assert profile["total_urls"] == 10

    def test_query_parameter_names(self):
        url = "https://example.com/search?q=test&page=2"
        with patch("src.recon.scoring.meaningful_query_pairs") as mock_mqp:
            mock_mqp.return_value = [("q", "test"), ("page", "2")]
            names = query_parameter_names(url)
            assert names == ["q", "page"]

    def test_resolve_priority_limit(self):
        filters = {"priority_limit": {"full": 200, "default": 100}}
        assert resolve_priority_limit(filters, "full") == 200
        assert resolve_priority_limit(filters, "other") == 100

        # Test profile-based selection
        profile = {"api_heavy": True, "total_urls": 50}
        filters = {"priority_limit": {"api_heavy": 300, "default": 100}}
        assert resolve_priority_limit(filters, "full", profile) == 300

        filters = {"priority_limit": {"small_target": 50, "default": 100}}
        profile = {"api_heavy": False, "total_urls": 50}
        assert resolve_priority_limit(filters, "full", profile) == 50

    def test_score_mode_bonus(self):
        scoring = {
            "modes": {
                "idor": {
                    "param_bonus": 10,
                    "parameter_keywords": ["id", "user"],
                    "path_keywords": ["account"],
                }
            }
        }
        url_with_id = "https://example.com/api?user_id=1"
        url_with_path = "https://example.com/account/settings"
        url_none = "https://example.com/home"

        with patch("src.recon.scoring.query_parameter_names") as mock_qpn:
            mock_qpn.side_effect = [["user_id"], [], []]
            assert score_mode_bonus(url_with_id, scoring, "idor") == 10
            assert score_mode_bonus(url_with_path, scoring, "idor") == 10
            assert score_mode_bonus(url_none, scoring, "idor") == 0

    def test_score_context_bonus(self):
        scoring = {"contexts": {"api_heavy": {"bonus": 5, "keywords": ["api", "v1"]}}}
        profile = {"api_heavy": True}
        assert score_context_bonus("https://example.com/api/test", scoring, profile) == 5
        assert score_context_bonus("https://example.com/home", scoring, profile) == 0

    def test_score_url(self):
        scoring = {"weights": {"admin": 10, "param": 5}, "custom_keyword_bonus": 2}
        filters = {"priority_keywords": ["secret"]}

        with (
            patch("src.recon.scoring.classify_endpoint") as mock_classify,
            patch("src.recon.scoring.is_auth_flow_endpoint") as mock_auth,
            patch("src.recon.scoring.has_meaningful_parameters") as mock_meaningful,
            patch("src.recon.scoring.is_low_value_endpoint") as mock_low_val,
            patch("src.recon.scoring.query_parameter_names") as mock_qpn,
            patch("src.recon.scoring.parameter_weight") as mock_pw,
        ):
            mock_classify.return_value = "API"
            mock_auth.return_value = False
            mock_meaningful.return_value = True
            mock_low_val.return_value = False
            mock_qpn.return_value = ["id"]
            mock_pw.return_value = 2

            # admin(10) + param_presence(5) + (pw(2)-1=1) + API(2) + custom_secret(2) = 20
            score = score_url("https://example.com/admin/secret?id=1", filters, scoring, "default")
            assert score == 20

    def test_score_url_precomputed(self):
        scoring = {"modes": {}}
        keyword_weights = {"api": 5, "param": 5}
        custom_priority_keywords = ["admin"]

        with patch("src.recon.scoring.parameter_weight") as mock_pw:
            mock_pw.return_value = 2  # id weight

            score = score_url_precomputed(
                lowered="https://example.com/api/admin",
                parameter_names=["id"],
                endpoint_type="API",
                is_auth_flow=True,
                has_meaningful_params=True,
                filters={},
                mode="default",
                profile=None,
                keyword_weights=keyword_weights,
                custom_priority_keywords=custom_priority_keywords,
                custom_keyword_bonus=2,
                scoring=scoring,
            )
            # api(5) + param_presence(5) + id_weight(2-1=1) + admin_custom(2) + API_bonus(2) + auth_bonus(3) = 18
            assert score == 18

    def test_flow_score(self):
        url = "https://example.com/oauth/callback?code=123&state=abc"
        with (
            patch("src.recon.scoring.query_parameter_names") as mock_qpn,
            patch("src.recon.scoring.is_auth_flow_endpoint") as mock_auth,
        ):
            mock_qpn.return_value = ["code", "state"]
            mock_auth.return_value = True

            # /oauth(5) + callback_param(5) + auth_endpoint(3) + token_state_params(2) = 15
            assert flow_score(url) == 15

    def test_rank_urls(self):
        urls = [
            "https://example.com/api/v1/users?id=1",
            "https://example.com/login",
            "https://example.com/static/js/main.js",
        ]
        filters = {"ignore_extensions": [".js"], "priority_limit": 10}
        scoring = {"weights": {"api": 5}, "custom_keyword_bonus": 2}

        with (
            patch("src.recon.scoring.build_flow_graph") as mock_flow_graph,
            patch("src.recon.scoring.derive_url_signals") as mock_signals,
            patch("src.recon.scoring.detect_trust_boundary") as mock_trust,
            patch("src.recon.scoring.normalize_ranked_scores") as mock_norm,
        ):
            mock_flow_graph.return_value = {"per_url": {}}
            mock_signals.side_effect = [{"api"}, set(), set()]
            mock_trust.return_value = {"level": "same-host", "score": 0}
            mock_norm.side_effect = lambda x: x  # just return as is

            ranked = rank_urls(urls, filters, scoring, "default")

            assert len(ranked) >= 1
            assert all(not r["url"].endswith(".js") for r in ranked)

    def test_compute_aggregate_risk_score(self):
        findings = [
            {"severity": "critical", "severity_score": 9.5, "category": "injection"},
            {"severity": "medium", "severity_score": 4.5, "category": "auth"},
        ]
        run_summary = {"run_id": "test-run"}

        with patch("src.recon.scoring.enrich_findings_with_model_severity") as mock_enrich:
            mock_enrich.return_value = findings
            report = compute_aggregate_risk_score(findings, run_summary)

            assert report["aggregate_score"] == 14.0  # 9.5 + 4.5
            assert report["max_severity"] == "critical"
            assert report["score_label"] == "critical"  # max_model_score 9.5 >= 8.8

    def test_compute_historical_score(self):
        endpoint = "https://example.com/api"
        current_score = 10.0
        past_runs = [
            {"score": 5.0, "timestamp": "2026-01-01", "findings": []},
            {"score": 7.0, "timestamp": "2026-01-02", "findings": ["bug1"]},
        ]

        result = compute_historical_score(endpoint, current_score, past_runs)
        assert result["endpoint"] == endpoint
        assert result["trend_direction"] == "increasing"
        assert result["risk_delta"] > 0
        assert result["finding_frequency"] == 0.5  # 1 out of 2 past runs
