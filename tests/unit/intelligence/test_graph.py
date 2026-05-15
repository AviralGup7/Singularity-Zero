"""Tests for intelligence graph module."""

from src.analysis.intelligence.endpoint_attack_graph import (
    AttackGraphEdge,
    AttackGraphNode,
    _identity_rank,
    _propagate_attack_confidence,
    _search_attack_chains,
    build_attack_graph,
)
from src.analysis.intelligence.endpoint_graphs import (
    build_auth_context_mapping,
    build_endpoint_relationship_graph,
    build_shared_parameter_tracking,
)
from src.analysis.intelligence.endpoint_graphs import (
    build_finding_graph as build_fg,
)


class TestEndpointRelationshipGraph:
    def test_returns_list(self) -> None:
        endpoints = [
            {
                "url": "https://example.com/api1",
                "host": "example.com",
                "query_parameters": ["id", "user_id"],
                "flow_labels": ["auth_flow"],
                "auth_contexts": ["authenticated"],
                "resource_group": "users",
                "endpoint_type": "API",
            },
            {
                "url": "https://example.com/api2",
                "host": "example.com",
                "query_parameters": ["id", "order_id"],
                "flow_labels": ["auth_flow"],
                "auth_contexts": ["authenticated"],
                "resource_group": "orders",
                "endpoint_type": "API",
            },
        ]
        result = build_endpoint_relationship_graph(endpoints)
        assert isinstance(result, list)

    def test_edges_have_source_url(self) -> None:
        endpoints = [
            {
                "url": "https://example.com/api1",
                "host": "example.com",
                "query_parameters": ["id"],
                "flow_labels": [],
                "auth_contexts": ["authenticated"],
                "resource_group": "",
                "endpoint_type": "API",
            },
            {
                "url": "https://example.com/api2",
                "host": "example.com",
                "query_parameters": ["id"],
                "flow_labels": [],
                "auth_contexts": ["authenticated"],
                "resource_group": "",
                "endpoint_type": "API",
            },
        ]
        result = build_endpoint_relationship_graph(endpoints)
        for edge in result:
            assert "source_url" in edge

    def test_edges_have_target_url(self) -> None:
        endpoints = [
            {
                "url": "https://example.com/api1",
                "host": "example.com",
                "query_parameters": ["id"],
                "flow_labels": [],
                "auth_contexts": ["authenticated"],
                "resource_group": "",
                "endpoint_type": "API",
            },
            {
                "url": "https://example.com/api2",
                "host": "example.com",
                "query_parameters": ["id"],
                "flow_labels": [],
                "auth_contexts": ["authenticated"],
                "resource_group": "",
                "endpoint_type": "API",
            },
        ]
        result = build_endpoint_relationship_graph(endpoints)
        for edge in result:
            assert "target_url" in edge

    def test_edges_have_relationship_types(self) -> None:
        endpoints = [
            {
                "url": "https://example.com/api1",
                "host": "example.com",
                "query_parameters": ["id"],
                "flow_labels": [],
                "auth_contexts": ["authenticated"],
                "resource_group": "",
                "endpoint_type": "API",
            },
            {
                "url": "https://example.com/api2",
                "host": "example.com",
                "query_parameters": ["id"],
                "flow_labels": [],
                "auth_contexts": ["authenticated"],
                "resource_group": "",
                "endpoint_type": "API",
            },
        ]
        result = build_endpoint_relationship_graph(endpoints)
        for edge in result:
            assert "relationship_types" in edge

    def test_edges_have_score(self) -> None:
        endpoints = [
            {
                "url": "https://example.com/api1",
                "host": "example.com",
                "query_parameters": ["id"],
                "flow_labels": [],
                "auth_contexts": ["authenticated"],
                "resource_group": "",
                "endpoint_type": "API",
            },
            {
                "url": "https://example.com/api2",
                "host": "example.com",
                "query_parameters": ["id"],
                "flow_labels": [],
                "auth_contexts": ["authenticated"],
                "resource_group": "",
                "endpoint_type": "API",
            },
        ]
        result = build_endpoint_relationship_graph(endpoints)
        for edge in result:
            assert "score" in edge

    def test_different_hosts_no_edges(self) -> None:
        endpoints = [
            {
                "url": "https://example.com/api1",
                "host": "example.com",
                "query_parameters": ["id"],
                "flow_labels": [],
                "auth_contexts": ["authenticated"],
                "resource_group": "",
                "endpoint_type": "API",
            },
            {
                "url": "https://other.com/api2",
                "host": "other.com",
                "query_parameters": ["id"],
                "flow_labels": [],
                "auth_contexts": ["authenticated"],
                "resource_group": "",
                "endpoint_type": "API",
            },
        ]
        result = build_endpoint_relationship_graph(endpoints)
        assert result == []

    def test_no_shared_attributes_no_edges(self) -> None:
        endpoints = [
            {
                "url": "https://example.com/api1",
                "host": "example.com",
                "query_parameters": ["a"],
                "flow_labels": [],
                "auth_contexts": ["public"],
                "resource_group": "users",
                "endpoint_type": "API",
            },
            {
                "url": "https://example.com/api2",
                "host": "example.com",
                "query_parameters": ["b"],
                "flow_labels": [],
                "auth_contexts": ["authenticated"],
                "resource_group": "orders",
                "endpoint_type": "ADMIN",
            },
        ]
        result = build_endpoint_relationship_graph(endpoints)
        assert result == []

    def test_respects_limit(self) -> None:
        endpoints = [
            {
                "url": f"https://example.com/api{i}",
                "host": "example.com",
                "query_parameters": ["id"],
                "flow_labels": [],
                "auth_contexts": ["authenticated"],
                "resource_group": "",
                "endpoint_type": "API",
            }
            for i in range(20)
        ]
        result = build_endpoint_relationship_graph(endpoints, limit=5)
        assert len(result) <= 5

    def test_sorted_by_score_descending(self) -> None:
        endpoints = [
            {
                "url": "https://example.com/api1",
                "host": "example.com",
                "query_parameters": ["id", "user_id"],
                "flow_labels": ["auth"],
                "auth_contexts": ["authenticated"],
                "resource_group": "users",
                "endpoint_type": "API",
            },
            {
                "url": "https://example.com/api2",
                "host": "example.com",
                "query_parameters": ["id", "user_id"],
                "flow_labels": ["auth"],
                "auth_contexts": ["authenticated"],
                "resource_group": "users",
                "endpoint_type": "API",
            },
            {
                "url": "https://example.com/api3",
                "host": "example.com",
                "query_parameters": ["id"],
                "flow_labels": [],
                "auth_contexts": ["authenticated"],
                "resource_group": "",
                "endpoint_type": "API",
            },
        ]
        result = build_endpoint_relationship_graph(endpoints)
        scores = [e["score"] for e in result]
        assert scores == sorted(scores, reverse=True)


class TestSharedParameterTracking:
    def test_returns_list(self) -> None:
        endpoints = [
            {
                "url": "https://example.com/api1",
                "host": "example.com",
                "query_parameters": ["id"],
                "auth_contexts": [],
                "endpoint_type": "API",
                "resource_group": "",
            },
            {
                "url": "https://example.com/api2",
                "host": "example.com",
                "query_parameters": ["id"],
                "auth_contexts": [],
                "endpoint_type": "API",
                "resource_group": "",
            },
        ]
        result = build_shared_parameter_tracking(endpoints)
        assert isinstance(result, list)

    def test_tracks_shared_parameters(self) -> None:
        endpoints = [
            {
                "url": "https://example.com/api1",
                "host": "example.com",
                "query_parameters": ["id"],
                "auth_contexts": [],
                "endpoint_type": "API",
                "resource_group": "",
            },
            {
                "url": "https://example.com/api2",
                "host": "example.com",
                "query_parameters": ["id"],
                "auth_contexts": [],
                "endpoint_type": "API",
                "resource_group": "",
            },
        ]
        result = build_shared_parameter_tracking(endpoints)
        assert len(result) > 0

    def test_result_has_parameter_key(self) -> None:
        endpoints = [
            {
                "url": "https://example.com/api1",
                "host": "example.com",
                "query_parameters": ["id"],
                "auth_contexts": [],
                "endpoint_type": "API",
                "resource_group": "",
            },
            {
                "url": "https://example.com/api2",
                "host": "example.com",
                "query_parameters": ["id"],
                "auth_contexts": [],
                "endpoint_type": "API",
                "resource_group": "",
            },
        ]
        result = build_shared_parameter_tracking(endpoints)
        assert all("parameter" in item for item in result)

    def test_result_has_endpoint_count(self) -> None:
        endpoints = [
            {
                "url": "https://example.com/api1",
                "host": "example.com",
                "query_parameters": ["id"],
                "auth_contexts": [],
                "endpoint_type": "API",
                "resource_group": "",
            },
            {
                "url": "https://example.com/api2",
                "host": "example.com",
                "query_parameters": ["id"],
                "auth_contexts": [],
                "endpoint_type": "API",
                "resource_group": "",
            },
        ]
        result = build_shared_parameter_tracking(endpoints)
        assert all("endpoint_count" in item for item in result)

    def test_only_parameters_shared_by_two_plus_endpoints(self) -> None:
        endpoints = [
            {
                "url": "https://example.com/api1",
                "host": "example.com",
                "query_parameters": ["id"],
                "auth_contexts": [],
                "endpoint_type": "API",
                "resource_group": "",
            },
            {
                "url": "https://example.com/api2",
                "host": "example.com",
                "query_parameters": ["other"],
                "auth_contexts": [],
                "endpoint_type": "API",
                "resource_group": "",
            },
        ]
        result = build_shared_parameter_tracking(endpoints)
        assert result == []


class TestAuthContextMapping:
    def test_returns_list(self) -> None:
        endpoints = [
            {
                "url": "https://example.com/api1",
                "host": "example.com",
                "auth_contexts": ["authenticated"],
                "signals": ["auth"],
                "resource_group": "",
            },
        ]
        result = build_auth_context_mapping(endpoints)
        assert isinstance(result, list)

    def test_result_has_context_key(self) -> None:
        endpoints = [
            {
                "url": "https://example.com/api1",
                "host": "example.com",
                "auth_contexts": ["authenticated", "public"],
                "signals": ["auth"],
                "resource_group": "",
            },
        ]
        result = build_auth_context_mapping(endpoints)
        assert all("context" in item for item in result)

    def test_result_has_endpoint_count(self) -> None:
        endpoints = [
            {
                "url": "https://example.com/api1",
                "host": "example.com",
                "auth_contexts": ["authenticated", "public"],
                "signals": ["auth"],
                "resource_group": "",
            },
        ]
        result = build_auth_context_mapping(endpoints)
        assert all("endpoint_count" in item for item in result)


class TestFindingGraph:
    def test_returns_dict(self) -> None:
        endpoints = [
            {
                "url": "https://example.com/api",
                "host": "example.com",
                "query_parameters": ["id"],
                "auth_contexts": ["authenticated"],
                "endpoint_key": "/api",
                "endpoint_base_key": "/api",
                "resource_group": "",
                "evidence_confidence": 0.5,
                "signals": [],
                "evidence_modules": [],
                "flow_labels": [],
                "attack_hints": [],
                "payload_suggestions": [],
                "response_diff": None,
                "response_snapshot": None,
                "parameter_sensitivity": 0,
                "trust_boundary": "same-host",
                "flow_score": 0,
                "normalized_score": 0.0,
                "signal_cooccurrence": {},
                "schema_markers": [],
                "score": 5,
                "signal_count": 0,
                "multi_signal_priority": [],
                "finding_reasoning": "",
                "decision": "MEDIUM",
                "decision_reason": "",
                "confidence_factors": [],
                "score_breakdown": [],
                "reason": "",
                "threat_surface_score": 0.0,
            },
        ]
        result = build_fg(endpoints)
        assert isinstance(result, dict)

    def test_has_nodes_key(self) -> None:
        endpoints = []
        result = build_fg(endpoints)
        assert "nodes" in result

    def test_has_edges_key(self) -> None:
        endpoints = []
        result = build_fg(endpoints)
        assert "edges" in result

    def test_nodes_have_id(self) -> None:
        endpoints = [
            {
                "url": "https://example.com/api",
                "host": "example.com",
                "query_parameters": ["id"],
                "auth_contexts": ["authenticated"],
                "endpoint_key": "/api",
                "endpoint_base_key": "/api",
                "resource_group": "",
                "evidence_confidence": 0.5,
                "signals": [],
                "evidence_modules": [],
                "flow_labels": [],
                "attack_hints": [],
                "payload_suggestions": [],
                "response_diff": None,
                "response_snapshot": None,
                "parameter_sensitivity": 0,
                "trust_boundary": "same-host",
                "flow_score": 0,
                "normalized_score": 0.0,
                "signal_cooccurrence": {},
                "schema_markers": [],
                "score": 5,
                "signal_count": 0,
                "multi_signal_priority": [],
                "finding_reasoning": "",
                "decision": "MEDIUM",
                "decision_reason": "",
                "confidence_factors": [],
                "score_breakdown": [],
                "reason": "",
                "threat_surface_score": 0.0,
            },
        ]
        result = build_fg(endpoints)
        for node in result["nodes"]:
            assert "id" in node

    def test_nodes_have_type(self) -> None:
        endpoints = [
            {
                "url": "https://example.com/api",
                "host": "example.com",
                "query_parameters": ["id"],
                "auth_contexts": ["authenticated"],
                "endpoint_key": "/api",
                "endpoint_base_key": "/api",
                "resource_group": "",
                "evidence_confidence": 0.5,
                "signals": [],
                "evidence_modules": [],
                "flow_labels": [],
                "attack_hints": [],
                "payload_suggestions": [],
                "response_diff": None,
                "response_snapshot": None,
                "parameter_sensitivity": 0,
                "trust_boundary": "same-host",
                "flow_score": 0,
                "normalized_score": 0.0,
                "signal_cooccurrence": {},
                "schema_markers": [],
                "score": 5,
                "signal_count": 0,
                "multi_signal_priority": [],
                "finding_reasoning": "",
                "decision": "MEDIUM",
                "decision_reason": "",
                "confidence_factors": [],
                "score_breakdown": [],
                "reason": "",
                "threat_surface_score": 0.0,
            },
        ]
        result = build_fg(endpoints)
        for node in result["nodes"]:
            assert "type" in node


class TestAttackGraph:
    def test_returns_dict(self) -> None:
        endpoints = [
            {
                "url": "https://example.com/api",
                "host": "example.com",
                "auth_contexts": ["authenticated", "public"],
                "endpoint_key": "/api",
                "endpoint_base_key": "/api",
                "resource_group": "",
                "evidence_confidence": 0.5,
            },
        ]
        result = build_attack_graph(endpoints)
        assert isinstance(result, dict)

    def test_has_nodes_key(self) -> None:
        endpoints = [
            {
                "url": "https://example.com/api",
                "host": "example.com",
                "auth_contexts": ["authenticated", "public"],
                "endpoint_key": "/api",
                "endpoint_base_key": "/api",
                "resource_group": "",
                "evidence_confidence": 0.5,
            },
        ]
        result = build_attack_graph(endpoints)
        assert "nodes" in result

    def test_has_edges_key(self) -> None:
        endpoints = [
            {
                "url": "https://example.com/api",
                "host": "example.com",
                "auth_contexts": ["authenticated", "public"],
                "endpoint_key": "/api",
                "endpoint_base_key": "/api",
                "resource_group": "",
                "evidence_confidence": 0.5,
            },
        ]
        result = build_attack_graph(endpoints)
        assert "edges" in result

    def test_has_chains_key(self) -> None:
        endpoints = [
            {
                "url": "https://example.com/api",
                "host": "example.com",
                "auth_contexts": ["authenticated", "public"],
                "endpoint_key": "/api",
                "endpoint_base_key": "/api",
                "resource_group": "",
                "evidence_confidence": 0.5,
            },
        ]
        result = build_attack_graph(endpoints)
        assert "chains" in result

    def test_has_endpoint_nodes_key(self) -> None:
        endpoints = [
            {
                "url": "https://example.com/api",
                "host": "example.com",
                "auth_contexts": ["authenticated", "public"],
                "endpoint_key": "/api",
                "endpoint_base_key": "/api",
                "resource_group": "",
                "evidence_confidence": 0.5,
            },
        ]
        result = build_attack_graph(endpoints)
        assert "endpoint_nodes" in result

    def test_nodes_have_id(self) -> None:
        endpoints = [
            {
                "url": "https://example.com/api",
                "host": "example.com",
                "auth_contexts": ["authenticated", "public"],
                "endpoint_key": "/api",
                "endpoint_base_key": "/api",
                "resource_group": "",
                "evidence_confidence": 0.5,
            },
        ]
        result = build_attack_graph(endpoints)
        for node in result["nodes"]:
            assert "id" in node

    def test_edges_have_source_target(self) -> None:
        endpoints = [
            {
                "url": "https://example.com/api",
                "host": "example.com",
                "auth_contexts": ["authenticated", "public"],
                "endpoint_key": "/api",
                "endpoint_base_key": "/api",
                "resource_group": "",
                "evidence_confidence": 0.5,
            },
        ]
        result = build_attack_graph(endpoints)
        for edge in result["edges"]:
            assert "source" in edge
            assert "target" in edge

    def test_empty_endpoints_returns_empty_graph(self) -> None:
        result = build_attack_graph([])
        assert result["nodes"] == []
        assert result["edges"] == []
        assert result["chains"] == []


class TestAttackGraphHelpers:
    def test_identity_rank_public(self) -> None:
        assert _identity_rank("public") == 0

    def test_identity_rank_authenticated(self) -> None:
        assert _identity_rank("authenticated") == 1

    def test_identity_rank_privileged(self) -> None:
        assert _identity_rank("privileged") == 2

    def test_identity_rank_admin(self) -> None:
        assert _identity_rank("admin") == 2

    def test_identity_rank_unknown(self) -> None:
        assert _identity_rank("unknown") == 1

    def test_propagate_confidence_returns_dict(self) -> None:
        nodes = {
            "a": AttackGraphNode(
                "a", "/api", "https://example.com/api", "public", "api", "example.com", 0.5
            ),
        }
        edges: dict[tuple[str, str, str], AttackGraphEdge] = {}
        result = _propagate_attack_confidence(nodes, edges)
        assert isinstance(result, dict)
        assert "a" in result

    def test_search_chains_returns_list(self) -> None:
        nodes: dict[str, AttackGraphNode] = {}
        edges: dict[tuple[str, str, str], AttackGraphEdge] = {}
        propagated: dict[str, float] = {}
        result = _search_attack_chains(nodes, edges, propagated, limit=5, max_depth=3)
        assert isinstance(result, list)
