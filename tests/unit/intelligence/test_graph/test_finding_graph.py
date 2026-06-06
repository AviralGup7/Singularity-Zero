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