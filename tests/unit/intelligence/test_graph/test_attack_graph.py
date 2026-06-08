from src.analysis.intelligence.endpoint_attack_graph import (
    build_attack_graph,
)


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
