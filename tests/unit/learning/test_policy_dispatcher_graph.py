import unittest

from src.decision.priority_queue import CorrelationPriorityQueue, ScanTarget
from src.intelligence.graph.attack_graph import AttackGraphEngine
from src.learning.policy_dispatcher import PolicyAutoDispatcher


class TestPolicyDispatcherGraph(unittest.TestCase):
    def test_attack_graph_boosts_entry_points(self):
        graph_engine = AttackGraphEngine()

        endpoints = [
            {"url": "https://example.com/api/v1/auth"},
            {"url": "https://example.com/admin/dashboard"},
        ]

        findings = [
            {
                "id": "f_rce_99",
                "url": "https://example.com/api/v1/auth",
                "title": "Remote Code Execution via Auth Deserialization",
                "category": "rce",
                "severity": "critical",
            }
        ]

        graph_engine.build_from_findings(findings, endpoints=endpoints)

        # Dispatcher with graph engine attached
        dispatcher = PolicyAutoDispatcher(attack_graph_engine=graph_engine)

        queue = CorrelationPriorityQueue()
        queue.push(
            ScanTarget(
                url="https://example.com/api/v1/auth", base_priority=2.0, current_priority=2.0
            )
        )
        queue.push(
            ScanTarget(url="https://example.com/other", base_priority=2.0, current_priority=2.0)
        )

        # Generate policy from graph
        policy = dispatcher.generate_policy()

        # The RCE chain has high risk (11.0), so entry point should have a boost of at least 5.0
        boosts = dict(policy.target_boosts)
        self.assertIn("https://example.com/api/v1/auth", boosts)
        self.assertGreaterEqual(boosts["https://example.com/api/v1/auth"], 5.0)

        # Dispatch to queue and assert priority is increased
        dispatcher.dispatch_to_queue(queue, policy)
        target = queue._url_map["https://example.com/api/v1/auth"]
        self.assertGreaterEqual(target.current_priority, 7.0)
