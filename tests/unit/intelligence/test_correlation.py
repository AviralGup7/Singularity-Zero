"""Tests for intelligence correlation module."""

from src.intelligence.correlation.engine import (
    ATTACK_CHAINS,
    SEVERITY_ESCALATION,
    calculate_compound_risk,
    correlate_findings,
    detect_multi_vector_endpoints,
)


class TestAttackChains:
    def test_attack_chains_is_dict(self) -> None:
        assert isinstance(ATTACK_CHAINS, dict)

    def test_attack_chains_not_empty(self) -> None:
        assert len(ATTACK_CHAINS) > 0

    def test_ssrf_idor_chain_exists(self) -> None:
        assert "ssrf_idor_chain" in ATTACK_CHAINS

    def test_auth_bypass_access_control_chain(self) -> None:
        assert "auth_bypass_access_control" in ATTACK_CHAINS

    def test_xss_token_hijack_chain(self) -> None:
        assert "xss_token_hijack" in ATTACK_CHAINS

    def test_each_chain_has_required_categories(self) -> None:
        for name, (categories, description, bonus) in ATTACK_CHAINS.items():
            assert isinstance(categories, tuple)
            assert len(categories) >= 2

    def test_each_chain_has_description(self) -> None:
        for name, (categories, description, bonus) in ATTACK_CHAINS.items():
            assert isinstance(description, str)
            assert len(description) > 0

    def test_each_chain_has_positive_bonus(self) -> None:
        for name, (categories, description, bonus) in ATTACK_CHAINS.items():
            assert bonus > 0

    def test_three_vector_chains_exist(self) -> None:
        three_vector = [n for n, (cats, _, _) in ATTACK_CHAINS.items() if len(cats) >= 3]
        assert len(three_vector) > 0


class TestCorrelateFindings:
    def test_returns_same_list(self) -> None:
        findings = [
            {
                "url": "https://example.com/api",
                "category": "ssrf",
                "module": "mod1",
                "score": 5,
                "evidence": {},
            }
        ]
        result = correlate_findings(findings)
        assert result is findings

    def test_single_finding_marked_not_multi_vector(self) -> None:
        findings = [
            {
                "url": "https://example.com/api",
                "category": "ssrf",
                "module": "mod1",
                "score": 5,
                "evidence": {},
            }
        ]
        result = correlate_findings(findings)
        assert result[0]["multi_vector"] is False

    def test_single_finding_has_empty_attack_chains(self) -> None:
        findings = [
            {
                "url": "https://example.com/api",
                "category": "ssrf",
                "module": "mod1",
                "score": 5,
                "evidence": {},
            }
        ]
        result = correlate_findings(findings)
        assert result[0]["attack_chains"] == []

    def test_single_finding_has_zero_correlation_bonus(self) -> None:
        findings = [
            {
                "url": "https://example.com/api",
                "category": "ssrf",
                "module": "mod1",
                "score": 5,
                "evidence": {},
            }
        ]
        result = correlate_findings(findings)
        assert result[0]["correlation_bonus"] == 0.0

    def test_multi_vector_detection(self) -> None:
        findings = [
            {
                "url": "https://example.com/api",
                "category": "ssrf",
                "module": "mod1",
                "score": 5,
                "evidence": {"endpoint_base_key": "/api"},
            },
            {
                "url": "https://example.com/api",
                "category": "idor",
                "module": "mod2",
                "score": 4,
                "evidence": {"endpoint_base_key": "/api"},
            },
        ]
        result = correlate_findings(findings)
        assert all(f["multi_vector"] is True for f in result)

    def test_attack_chain_detection(self) -> None:
        findings = [
            {
                "url": "https://example.com/api",
                "category": "ssrf",
                "module": "mod1",
                "score": 5,
                "evidence": {"endpoint_base_key": "/api"},
            },
            {
                "url": "https://example.com/api",
                "category": "idor",
                "module": "mod2",
                "score": 4,
                "evidence": {"endpoint_base_key": "/api"},
            },
        ]
        result = correlate_findings(findings)
        assert any(f["attack_chains"] for f in result)

    def test_correlation_bonus_positive_for_multi_vector(self) -> None:
        findings = [
            {
                "url": "https://example.com/api",
                "category": "ssrf",
                "module": "mod1",
                "score": 5,
                "evidence": {"endpoint_base_key": "/api"},
            },
            {
                "url": "https://example.com/api",
                "category": "idor",
                "module": "mod2",
                "score": 4,
                "evidence": {"endpoint_base_key": "/api"},
            },
        ]
        result = correlate_findings(findings)
        assert all(f["correlation_bonus"] > 0 for f in result)

    def test_compound_risk_score_increases(self) -> None:
        findings = [
            {
                "url": "https://example.com/api",
                "category": "ssrf",
                "module": "mod1",
                "score": 5,
                "evidence": {"endpoint_base_key": "/api"},
            },
            {
                "url": "https://example.com/api",
                "category": "idor",
                "module": "mod2",
                "score": 4,
                "evidence": {"endpoint_base_key": "/api"},
            },
        ]
        result = correlate_findings(findings)
        for f in result:
            assert f["compound_risk_score"] >= f["score"]

    def test_confidence_boosted_by_correlation(self) -> None:
        findings = [
            {
                "url": "https://example.com/api",
                "category": "ssrf",
                "module": "mod1",
                "score": 5,
                "confidence": 0.5,
                "evidence": {"endpoint_base_key": "/api"},
            },
            {
                "url": "https://example.com/api",
                "category": "idor",
                "module": "mod2",
                "score": 4,
                "confidence": 0.4,
                "evidence": {"endpoint_base_key": "/api"},
            },
        ]
        result = correlate_findings(findings)
        for f in result:
            assert f["confidence"] >= 0.5

    def test_explanation_includes_chain_description(self) -> None:
        findings = [
            {
                "url": "https://example.com/api",
                "category": "ssrf",
                "module": "mod1",
                "score": 5,
                "evidence": {"endpoint_base_key": "/api"},
            },
            {
                "url": "https://example.com/api",
                "category": "idor",
                "module": "mod2",
                "score": 4,
                "evidence": {"endpoint_base_key": "/api"},
            },
        ]
        result = correlate_findings(findings)
        assert any("Attack chain detected" in f.get("explanation", "") for f in result)

    def test_empty_findings_returns_empty(self) -> None:
        result = correlate_findings([])
        assert result == []

    def test_different_endpoints_no_correlation(self) -> None:
        findings = [
            {
                "url": "https://example.com/api1",
                "category": "ssrf",
                "module": "mod1",
                "score": 5,
                "evidence": {"endpoint_base_key": "/api1"},
            },
            {
                "url": "https://example.com/api2",
                "category": "idor",
                "module": "mod2",
                "score": 4,
                "evidence": {"endpoint_base_key": "/api2"},
            },
        ]
        result = correlate_findings(findings)
        assert all(f["multi_vector"] is False for f in result)

    def test_duplicate_same_module_not_marked_multi_vector(self) -> None:
        findings = [
            {
                "url": "https://example.com/api",
                "category": "ssrf",
                "module": "mod1",
                "score": 5,
                "evidence": {"endpoint_base_key": "/api"},
            },
            {
                "url": "https://example.com/api",
                "category": "ssrf",
                "module": "mod1",
                "score": 4,
                "evidence": {"endpoint_base_key": "/api"},
            },
        ]

        result = correlate_findings(findings)

        assert all(f["multi_vector"] is False for f in result)
        assert all(f["attack_chains"] == [] for f in result)
        assert all(f["correlation_bonus"] == 0.0 for f in result)


class TestDetectMultiVectorEndpoints:
    def test_returns_list(self) -> None:
        findings = [
            {
                "url": "https://example.com/api",
                "category": "ssrf",
                "module": "mod1",
                "score": 5,
                "evidence": {"endpoint_base_key": "/api"},
                "multi_vector": True,
                "attack_chains": [],
                "compound_risk_score": 5,
            },
            {
                "url": "https://example.com/api",
                "category": "idor",
                "module": "mod2",
                "score": 4,
                "evidence": {"endpoint_base_key": "/api"},
                "multi_vector": True,
                "attack_chains": [],
                "compound_risk_score": 5,
            },
        ]
        result = detect_multi_vector_endpoints(findings)
        assert isinstance(result, list)

    def test_only_multi_vector_endpoints(self) -> None:
        findings = [
            {
                "url": "https://example.com/api",
                "category": "ssrf",
                "module": "mod1",
                "score": 5,
                "evidence": {"endpoint_base_key": "/api"},
                "multi_vector": True,
                "attack_chains": [],
                "compound_risk_score": 5,
            },
            {
                "url": "https://example.com/api",
                "category": "idor",
                "module": "mod2",
                "score": 4,
                "evidence": {"endpoint_base_key": "/api"},
                "multi_vector": True,
                "attack_chains": [],
                "compound_risk_score": 5,
            },
        ]
        result = detect_multi_vector_endpoints(findings)
        assert all(item["finding_count"] >= 2 for item in result)

    def test_result_sorted_by_risk(self) -> None:
        findings = [
            {
                "url": "https://example.com/api1",
                "category": "ssrf",
                "module": "mod1",
                "score": 5,
                "evidence": {"endpoint_base_key": "/api1"},
                "multi_vector": True,
                "attack_chains": [],
                "compound_risk_score": 10,
            },
            {
                "url": "https://example.com/api1",
                "category": "idor",
                "module": "mod2",
                "score": 4,
                "evidence": {"endpoint_base_key": "/api1"},
                "multi_vector": True,
                "attack_chains": [],
                "compound_risk_score": 10,
            },
            {
                "url": "https://example.com/api2",
                "category": "xss",
                "module": "mod3",
                "score": 3,
                "evidence": {"endpoint_base_key": "/api2"},
                "multi_vector": True,
                "attack_chains": [],
                "compound_risk_score": 5,
            },
            {
                "url": "https://example.com/api2",
                "category": "csrf",
                "module": "mod4",
                "score": 2,
                "evidence": {"endpoint_base_key": "/api2"},
                "multi_vector": True,
                "attack_chains": [],
                "compound_risk_score": 5,
            },
        ]
        result = detect_multi_vector_endpoints(findings)
        scores = [item["compound_risk_score"] for item in result]
        assert scores == sorted(scores, reverse=True)

    def test_result_has_endpoint_key(self) -> None:
        findings = [
            {
                "url": "https://example.com/api",
                "category": "ssrf",
                "module": "mod1",
                "score": 5,
                "evidence": {"endpoint_base_key": "/api"},
                "multi_vector": True,
                "attack_chains": [],
                "compound_risk_score": 5,
            },
            {
                "url": "https://example.com/api",
                "category": "idor",
                "module": "mod2",
                "score": 4,
                "evidence": {"endpoint_base_key": "/api"},
                "multi_vector": True,
                "attack_chains": [],
                "compound_risk_score": 5,
            },
        ]
        result = detect_multi_vector_endpoints(findings)
        assert all("endpoint_key" in item for item in result)

    def test_result_has_categories(self) -> None:
        findings = [
            {
                "url": "https://example.com/api",
                "category": "ssrf",
                "module": "mod1",
                "score": 5,
                "evidence": {"endpoint_base_key": "/api"},
                "multi_vector": True,
                "attack_chains": [],
                "compound_risk_score": 5,
            },
            {
                "url": "https://example.com/api",
                "category": "idor",
                "module": "mod2",
                "score": 4,
                "evidence": {"endpoint_base_key": "/api"},
                "multi_vector": True,
                "attack_chains": [],
                "compound_risk_score": 5,
            },
        ]
        result = detect_multi_vector_endpoints(findings)
        assert all("categories" in item for item in result)

    def test_empty_findings_returns_empty(self) -> None:
        result = detect_multi_vector_endpoints([])
        assert result == []

    def test_duplicate_same_module_not_reported_as_multi_vector_endpoint(self) -> None:
        findings = [
            {
                "url": "https://example.com/api",
                "category": "ssrf",
                "module": "mod1",
                "score": 5,
                "evidence": {"endpoint_base_key": "/api"},
                "multi_vector": False,
                "attack_chains": [],
                "compound_risk_score": 5,
            },
            {
                "url": "https://example.com/api",
                "category": "ssrf",
                "module": "mod1",
                "score": 4,
                "evidence": {"endpoint_base_key": "/api"},
                "multi_vector": False,
                "attack_chains": [],
                "compound_risk_score": 5,
            },
        ]

        result = detect_multi_vector_endpoints(findings)

        assert result == []


class TestCalculateCompoundRisk:
    def test_returns_dict(self) -> None:
        findings = [
            {
                "url": "https://example.com/api",
                "category": "ssrf",
                "module": "mod1",
                "score": 5,
                "severity": "high",
                "multi_vector": True,
                "attack_chains": ["ssrf_idor_chain"],
                "compound_risk_score": 7,
            }
        ]
        result = calculate_compound_risk(findings)
        assert isinstance(result, dict)

    def test_has_total_findings(self) -> None:
        findings = [
            {
                "url": "https://example.com/api",
                "category": "ssrf",
                "module": "mod1",
                "score": 5,
                "severity": "high",
                "multi_vector": True,
                "attack_chains": ["ssrf_idor_chain"],
                "compound_risk_score": 7,
            }
        ]
        result = calculate_compound_risk(findings)
        assert result["total_findings"] == 1

    def test_has_multi_vector_count(self) -> None:
        findings = [
            {
                "url": "https://example.com/api",
                "category": "ssrf",
                "module": "mod1",
                "score": 5,
                "severity": "high",
                "multi_vector": True,
                "attack_chains": ["ssrf_idor_chain"],
                "compound_risk_score": 7,
            }
        ]
        result = calculate_compound_risk(findings)
        assert "multi_vector_findings" in result

    def test_has_attack_chains_detected(self) -> None:
        findings = [
            {
                "url": "https://example.com/api",
                "category": "ssrf",
                "module": "mod1",
                "score": 5,
                "severity": "high",
                "multi_vector": True,
                "attack_chains": ["ssrf_idor_chain"],
                "compound_risk_score": 7,
            }
        ]
        result = calculate_compound_risk(findings)
        assert result["attack_chains_detected"] == 1

    def test_has_highest_compound_risk(self) -> None:
        findings = [
            {
                "url": "https://example.com/api",
                "category": "ssrf",
                "module": "mod1",
                "score": 5,
                "severity": "high",
                "multi_vector": True,
                "attack_chains": ["ssrf_idor_chain"],
                "compound_risk_score": 7,
            }
        ]
        result = calculate_compound_risk(findings)
        assert "highest_compound_risk" in result

    def test_has_risk_distribution(self) -> None:
        findings = [
            {
                "url": "https://example.com/api",
                "category": "ssrf",
                "module": "mod1",
                "score": 5,
                "severity": "high",
                "multi_vector": True,
                "attack_chains": [],
                "compound_risk_score": 7,
            }
        ]
        result = calculate_compound_risk(findings)
        assert "risk_distribution" in result
        assert result["risk_distribution"]["high"] == 1

    def test_empty_findings(self) -> None:
        result = calculate_compound_risk([])
        assert result["total_findings"] == 0
        assert result["attack_chains_detected"] == 0
        assert result["highest_compound_risk"] == 0


class TestSeverityEscalation:
    def test_escalation_has_low(self) -> None:
        assert "low" in SEVERITY_ESCALATION

    def test_escalation_has_medium(self) -> None:
        assert "medium" in SEVERITY_ESCALATION

    def test_escalation_has_high(self) -> None:
        assert "high" in SEVERITY_ESCALATION

    def test_escalation_has_min_chain_count(self) -> None:
        for level, config in SEVERITY_ESCALATION.items():
            assert "min_chain_count" in config

    def test_escalation_has_escalated_to(self) -> None:
        for level, config in SEVERITY_ESCALATION.items():
            assert "escalated_to" in config
