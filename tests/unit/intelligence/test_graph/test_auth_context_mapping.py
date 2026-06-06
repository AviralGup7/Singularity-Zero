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