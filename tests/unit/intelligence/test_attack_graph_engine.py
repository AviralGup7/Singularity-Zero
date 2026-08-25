import unittest

from src.intelligence.graph.attack_graph import (
    AttackChain,
    AttackGraphEngine,
    GraphEdge,
    GraphNode,
)


class TestAttackGraphEngine(unittest.TestCase):
    def test_build_graph_and_synthesize_chains(self):
        engine = AttackGraphEngine()

        endpoints = [
            {"url": "https://example.com/login"},
            {"url": "https://example.com/api/users"},
        ]

        findings = [
            {
                "id": "f_01",
                "url": "https://example.com/login",
                "title": "SQL Injection in User Login",
                "category": "sqli",
                "severity": "critical",
            },
            {
                "id": "f_02",
                "url": "https://example.com/api/users",
                "title": "Broken Access Control / IDOR",
                "category": "idor",
                "severity": "high",
            },
        ]

        engine.build_from_findings(findings, endpoints=endpoints)

        # Compute multi-hop attack paths from entry point
        chains = engine.find_shortest_attack_paths("asset:https://example.com/login")
        self.assertGreaterEqual(len(chains), 1)

        primary_chain = chains[0]
        self.assertIsInstance(primary_chain, AttackChain)
        self.assertEqual(primary_chain.entry_point_id, "asset:https://example.com/login")
        self.assertTrue(primary_chain.target_id.startswith("impact:takeover:"))
        self.assertEqual(primary_chain.hop_count, 2)
        self.assertGreater(primary_chain.total_risk, 10.0)

        # Export full graph
        exported = engine.export_graph()
        self.assertGreaterEqual(exported["total_nodes"], 4)
        self.assertGreaterEqual(len(exported["chains"]), 2)
