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