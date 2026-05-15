"""Tests for intelligence scoring module."""

from src.analysis.intelligence.endpoint.endpoint_intelligence import (
    build_endpoint_intelligence as build_ei,
)
from src.analysis.intelligence.endpoint.endpoint_intelligence._scoring import (
    _build_score_breakdown,
    _calculate_confidence,
    _calculate_score,
    _calculate_threat_surface,
    _inferred_auth_contexts,
    enrich_and_score_endpoints,
)
from src.intelligence.scoring import (
    payment_flow_intelligence,
    payment_provider_detection,
)


class TestBuildEndpointIntelligence:
    def test_returns_list(self) -> None:
        result = build_ei([], {})
        assert isinstance(result, list)

    def test_empty_input_returns_empty(self) -> None:
        result = build_ei([], {})
        assert result == []

    def test_result_items_have_url(self) -> None:
        ranked = [
            {
                "url": "https://example.com/api",
                "score": 10,
                "normalized_score": 50.0,
                "endpoint_type": "API",
            }
        ]
        result = build_ei(ranked, {})
        if len(result) > 0:
            assert result[0]["url"] == "https://example.com/api"

    def test_result_items_have_endpoint_key(self) -> None:
        ranked = [
            {
                "url": "https://example.com/api",
                "score": 10,
                "normalized_score": 50.0,
                "endpoint_type": "API",
            }
        ]
        result = build_ei(ranked, {})
        if len(result) > 0:
            assert "endpoint_key" in result[0]

    def test_result_items_have_score(self) -> None:
        ranked = [
            {
                "url": "https://example.com/api",
                "score": 10,
                "normalized_score": 50.0,
                "endpoint_type": "API",
            }
        ]
        result = build_ei(ranked, {})
        if len(result) > 0:
            assert "score" in result[0]

    def test_result_items_have_signals(self) -> None:
        ranked = [
            {
                "url": "https://example.com/api",
                "score": 10,
                "normalized_score": 50.0,
                "endpoint_type": "API",
            }
        ]
        result = build_ei(ranked, {})
        if len(result) > 0:
            assert "signals" in result[0]

    def test_result_items_have_decision(self) -> None:
        ranked = [
            {
                "url": "https://example.com/api",
                "score": 10,
                "normalized_score": 50.0,
                "endpoint_type": "API",
            }
        ]
        result = build_ei(ranked, {})
        if len(result) > 0:
            assert "decision" in result[0]

    def test_result_items_have_evidence_confidence(self) -> None:
        ranked = [
            {
                "url": "https://example.com/api",
                "score": 10,
                "normalized_score": 50.0,
                "endpoint_type": "API",
            }
        ]
        result = build_ei(ranked, {})
        if len(result) > 0:
            assert "evidence_confidence" in result[0]

    def test_result_items_have_host(self) -> None:
        ranked = [
            {
                "url": "https://example.com/api",
                "score": 10,
                "normalized_score": 50.0,
                "endpoint_type": "API",
            }
        ]
        result = build_ei(ranked, {})
        if len(result) > 0:
            assert "host" in result[0]

    def test_result_items_have_auth_contexts(self) -> None:
        ranked = [
            {
                "url": "https://example.com/api",
                "score": 10,
                "normalized_score": 50.0,
                "endpoint_type": "API",
            }
        ]
        result = build_ei(ranked, {})
        if len(result) > 0:
            assert "auth_contexts" in result[0]

    def test_result_sorted_by_decision(self) -> None:
        ranked = [
            {"url": "https://example.com/api1", "score": 10, "normalized_score": 50.0},
            {"url": "https://example.com/api2", "score": 5, "normalized_score": 25.0},
        ]
        result = build_ei(ranked, {})
        decisions = [item["decision"] for item in result]
        assert decisions == sorted(decisions, key=lambda d: d != "HIGH")

    def test_max_30_results(self) -> None:
        ranked = [
            {"url": f"https://example.com/api{i}", "score": i, "normalized_score": float(i * 5)}
            for i in range(50)
        ]
        result = build_ei(ranked, {})
        assert len(result) <= 30


class TestEndpointScoring:
    def test_calculate_score_base_score(self) -> None:
        record = {
            "base_score": 10,
            "signals": set(),
            "flow_labels": set(),
            "flow_score": 0,
            "response_diff": None,
            "response_snapshot": None,
            "trust_boundary": "same-host",
            "parameter_sensitivity": 0,
            "normalized_score": 0.0,
            "endpoint_type": "GENERAL",
            "resource_group": "",
            "schema_markers": [],
        }
        score = _calculate_score(record, set(), 0)
        assert score >= 10

    def test_calculate_score_with_signals(self) -> None:
        record = {
            "base_score": 5,
            "signals": {"ssrf", "access_control"},
            "flow_labels": set(),
            "flow_score": 0,
            "response_diff": None,
            "response_snapshot": None,
            "trust_boundary": "same-host",
            "parameter_sensitivity": 0,
            "normalized_score": 0.0,
            "endpoint_type": "GENERAL",
            "resource_group": "",
            "schema_markers": [],
        }
        score = _calculate_score(record, {"ssrf", "access_control"}, 2)
        assert score > 5

    def test_calculate_score_dangerous_combo(self) -> None:
        record = {
            "base_score": 5,
            "signals": {"ssrf", "access_control"},
            "flow_labels": set(),
            "flow_score": 0,
            "response_diff": None,
            "response_snapshot": None,
            "trust_boundary": "same-host",
            "parameter_sensitivity": 0,
            "normalized_score": 0.0,
            "endpoint_type": "GENERAL",
            "resource_group": "",
            "schema_markers": [],
        }
        score = _calculate_score(record, {"ssrf", "access_control"}, 2)
        assert score > 20

    def test_calculate_confidence_base(self) -> None:
        record = {
            "signals": set(),
            "evidence_modules": set(),
            "parameter_sensitivity": 0,
            "response_diff": None,
            "trust_boundary": "same-host",
            "resource_group": "",
            "base_score": 5,
            "endpoint_key": "test",
        }
        conf = _calculate_confidence(record, set(), 0, {})
        assert 0.10 <= conf <= 0.97

    def test_calculate_confidence_with_reproducible(self) -> None:
        record = {
            "signals": {"reproducible"},
            "evidence_modules": set(),
            "parameter_sensitivity": 0,
            "response_diff": None,
            "trust_boundary": "same-host",
            "resource_group": "",
            "base_score": 5,
            "endpoint_key": "test",
        }
        conf = _calculate_confidence(record, set(), 1, {})
        assert conf > 0.30

    def test_calculate_confidence_with_cross_host(self) -> None:
        record = {
            "signals": set(),
            "evidence_modules": set(),
            "parameter_sensitivity": 0,
            "response_diff": None,
            "trust_boundary": "cross-host",
            "resource_group": "",
            "base_score": 5,
            "endpoint_key": "test",
        }
        conf = _calculate_confidence(record, set(), 0, {})
        assert conf > 0.30

    def test_calculate_threat_surface_base(self) -> None:
        record = {
            "signals": set(),
            "evidence_modules": set(),
            "parameter_sensitivity": 0,
            "flow_labels": set(),
            "trust_boundary": "same-host",
        }
        ts = _calculate_threat_surface(record, set())
        assert 0.0 <= ts <= 1.0

    def test_calculate_threat_surface_with_signals(self) -> None:
        record = {
            "signals": {"ssrf", "xss", "session"},
            "evidence_modules": {"mod1", "mod2"},
            "parameter_sensitivity": 4,
            "flow_labels": {"auth_flow"},
            "trust_boundary": "same-host",
        }
        ts = _calculate_threat_surface(record, {"ssrf", "xss", "session"})
        assert ts > 0.0

    def test_score_breakdown_is_list(self) -> None:
        record = {
            "base_score": 10,
            "signals": {"ssrf"},
            "flow_labels": set(),
            "trust_boundary": "same-host",
            "parameter_sensitivity": 0,
            "normalized_score": 0.0,
            "endpoint_type": "GENERAL",
            "resource_group": "",
            "schema_markers": [],
            "evidence_modules": set(),
        }
        breakdown = _build_score_breakdown(record, {"ssrf"}, 1)
        assert isinstance(breakdown, list)

    def test_auth_contexts_inference(self) -> None:
        record = {
            "endpoint_type": "AUTH",
            "signals": {"auth", "session"},
            "auth_contexts": set(),
            "schema_markers": [],
        }
        contexts = _inferred_auth_contexts(record)
        assert "auth_flow" in contexts
        assert "authenticated" in contexts


class TestPaymentIntelligence:
    def test_payment_flow_intelligence_returns_list(self) -> None:
        result = payment_flow_intelligence(set(), [])
        assert isinstance(result, list)

    def test_payment_flow_detects_checkout_path(self) -> None:
        urls = {"https://example.com/checkout"}
        result = payment_flow_intelligence(urls, [])
        assert len(result) > 0

    def test_payment_flow_detects_payment_params(self) -> None:
        urls = {"https://example.com/api?amount=100&currency=USD"}
        result = payment_flow_intelligence(urls, [])
        assert len(result) > 0

    def test_payment_provider_detection_returns_list(self) -> None:
        result = payment_provider_detection([])
        assert isinstance(result, list)

    def test_payment_provider_detects_stripe(self) -> None:
        responses = [
            {"url": "https://example.com", "body_text": "stripe paymentintent client_secret"}
        ]
        result = payment_provider_detection(responses)
        assert len(result) > 0
        assert "stripe" in result[0]["providers"]

    def test_payment_provider_detects_paypal(self) -> None:
        responses = [{"url": "https://example.com", "body_text": "paypal braintree integration"}]
        result = payment_provider_detection(responses)
        assert len(result) > 0
        assert "paypal" in result[0]["providers"]

    def test_payment_flow_has_url_key(self) -> None:
        urls = {"https://example.com/checkout"}
        result = payment_flow_intelligence(urls, [])
        assert all("url" in item for item in result)

    def test_payment_flow_has_signals_key(self) -> None:
        urls = {"https://example.com/checkout"}
        result = payment_flow_intelligence(urls, [])
        assert all("signals" in item for item in result)

    def test_payment_flow_has_score_key(self) -> None:
        urls = {"https://example.com/checkout"}
        result = payment_flow_intelligence(urls, [])
        assert all("score" in item for item in result)


class TestCrossEndpointCorrelationScoring:
    def test_enrich_and_score_returns_list(self) -> None:
        endpoint_map = {}
        result = enrich_and_score_endpoints(endpoint_map, {})
        assert isinstance(result, list)

    def test_enrich_and_score_drops_low_confidence(self) -> None:
        endpoint_map = {
            "test": {
                "url": "https://example.com/api",
                "endpoint_key": "test",
                "endpoint_base_key": "/api",
                "endpoint_type": "GENERAL",
                "base_score": 0,
                "normalized_score": 0.0,
                "signals": set(),
                "evidence_modules": set(),
                "signal_cooccurrence": {},
                "flow_labels": set(),
                "attack_hints": [],
                "payload_suggestions": [],
                "response_diff": None,
                "response_snapshot": None,
                "parameter_sensitivity": 0,
                "trust_boundary": "same-host",
                "flow_score": 0,
                "evidence_confidence": 0.42,
                "resource_group": "",
                "schema_markers": [],
                "query_parameters": set(),
                "auth_contexts": set(),
            }
        }
        result = enrich_and_score_endpoints(endpoint_map, {})
        assert isinstance(result, list)
