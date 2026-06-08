from src.analysis.intelligence.endpoint_graphs import (
    build_endpoint_relationship_graph,
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
