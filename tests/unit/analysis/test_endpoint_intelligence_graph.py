import unittest
from typing import Any

from src.analysis.intelligence.endpoint.endpoint_intelligence import (
    build_attack_graph,
    build_auth_context_mapping,
    build_endpoint_relationship_graph,
    build_finding_graph,
    build_shared_parameter_tracking,
)


class EndpointIntelligenceGraphTests(unittest.TestCase):
    def test_cross_endpoint_relationships_and_auth_mapping_are_derived(self) -> None:
        users_url = "https://api.example.com/api/users?id=1&tenant_id=t1"
        accounts_url = "https://api.example.com/api/accounts?id=1&tenant_id=t1&role=admin"

        endpoint_intelligence = [
            {
                "url": users_url,
                "host": "api.example.com",
                "query_parameters": ["id", "tenant_id"],
                "flow_labels": ["auth_flow"],
                "auth_contexts": ["public", "authenticated"],
                "resource_group": "users",
                "endpoint_type": "API",
                "signals": ["auth", "json"],
            },
            {
                "url": accounts_url,
                "host": "api.example.com",
                "query_parameters": ["id", "tenant_id", "role"],
                "flow_labels": [],
                "auth_contexts": ["authenticated", "privileged"],
                "resource_group": "accounts",
                "endpoint_type": "API",
                "signals": ["access_control", "json"],
            },
        ]

        graph = build_endpoint_relationship_graph(endpoint_intelligence)
        self.assertTrue(graph)
        edge = next(
            item
            for item in graph
            if item["source_url"] in {users_url, accounts_url}
            and item["target_url"] in {users_url, accounts_url}
        )
        self.assertIn("shared_parameters", edge["relationship_types"])
        self.assertIn("tenant_id", edge["shared_parameters"])

        parameter_tracking = build_shared_parameter_tracking(endpoint_intelligence)
        tenant_entry = next(item for item in parameter_tracking if item["parameter"] == "tenant_id")
        self.assertEqual(tenant_entry["endpoint_count"], 2)
        self.assertIn("authenticated", tenant_entry["auth_contexts"])

        auth_map = build_auth_context_mapping(endpoint_intelligence)
        contexts = {item["context"]: item for item in auth_map}
        self.assertIn("authenticated", contexts)
        self.assertGreaterEqual(contexts["authenticated"]["endpoint_count"], 2)
        self.assertIn("mixed", contexts)

    def test_finding_graph_derives_required_node_and_edge_types(self) -> None:
        users_url = "https://api.example.com/api/users?id=1&tenant_id=t1"
        accounts_url = "https://api.example.com/api/accounts?id=1&tenant_id=t1&role=admin"
        endpoint_intelligence = [
            {
                "url": users_url,
                "host": "api.example.com",
                "query_parameters": ["id", "tenant_id"],
                "auth_contexts": ["authenticated"],
            },
            {
                "url": accounts_url,
                "host": "api.example.com",
                "query_parameters": ["id", "tenant_id", "role"],
                "auth_contexts": ["authenticated", "privileged"],
            },
        ]
        analysis_results: dict[str, list[dict[str, Any]]] = {
            "flow_detector": [{"label": "auth_flow", "chain": [users_url, accounts_url]}],
            "token_leak_detector": [
                {
                    "url": users_url,
                    "endpoint_key": "users",
                    "location": "query_parameter",
                    "leak_count": 2,
                }
            ],
            "referer_propagation_tracking": [
                {
                    "url": users_url,
                    "target_url": "https://cdn.example.net/collect",
                    "parameter": "token",
                }
            ],
        }

        graph = build_finding_graph(endpoint_intelligence, analysis_results)
        node_types = {item["type"] for item in graph["nodes"]}
        edge_types = {item["type"] for item in graph["edges"]}

        self.assertTrue({"endpoint", "parameter", "token", "user_role"}.issubset(node_types))
        self.assertTrue({"calls", "depends_on", "leaks_to"}.issubset(edge_types))

    def test_attack_graph_builds_required_edge_types_and_chains(self) -> None:
        login_url = "https://api.example.com/auth/login?tenant_id=t1"
        redirect_url = "https://api.example.com/oauth/callback?tenant_id=t1"
        account_url = "https://api.example.com/api/account?id=1&tenant_id=t1"

        endpoint_intelligence = [
            {
                "url": login_url,
                "endpoint_key": "login",
                "endpoint_base_key": "auth/login",
                "host": "api.example.com",
                "query_parameters": ["tenant_id"],
                "auth_contexts": ["public", "authenticated"],
                "resource_group": "auth",
                "evidence_confidence": 0.72,
            },
            {
                "url": redirect_url,
                "endpoint_key": "callback",
                "endpoint_base_key": "oauth/callback",
                "host": "api.example.com",
                "query_parameters": ["tenant_id", "id"],
                "auth_contexts": ["authenticated", "privileged"],
                "resource_group": "auth",
                "evidence_confidence": 0.74,
            },
            {
                "url": account_url,
                "endpoint_key": "account",
                "endpoint_base_key": "api/account",
                "host": "api.example.com",
                "query_parameters": ["id", "tenant_id"],
                "auth_contexts": ["authenticated", "privileged"],
                "resource_group": "accounts",
                "evidence_confidence": 0.78,
            },
        ]

        analysis_results: dict[str, list[dict[str, Any]]] = {
            "redirect_chain_analyzer": [
                {
                    "url": login_url,
                    "final_url": redirect_url,
                    "cross_host": False,
                }
            ],
            "referer_propagation_tracking": [
                {
                    "url": redirect_url,
                    "external_references": ["https://cdn.example.net/collect"],
                    "sensitive_params": ["tenant_id"],
                    "propagation_risk": True,
                }
            ],
            "state_transition_analyzer": [
                {
                    "url": account_url,
                    "mutated_url": "https://api.example.com/api/account?id=1&tenant_id=t2",
                    "parameter": "tenant_id",
                    "original_value": "t1",
                    "mutated_value": "t2",
                    "state_mismatch": True,
                }
            ],
        }

        attack_graph = build_attack_graph(endpoint_intelligence, analysis_results)
        edge_types = {item["type"] for item in attack_graph.get("edges", [])}

        self.assertTrue(
            {
                "leaks_to",
                "redirects_to",
                "shares_identifier_with",
                "auth_context_switch",
                "state_transition",
            }.issubset(edge_types)
        )
        self.assertTrue(attack_graph.get("chains"))
        top_chain = attack_graph["chains"][0]
        self.assertGreaterEqual(float(top_chain.get("confidence", 0.0)), 0.3)
        self.assertGreaterEqual(len(top_chain.get("steps", [])), 2)


if __name__ == "__main__":
    unittest.main()
