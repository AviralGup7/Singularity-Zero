import unittest

from src.decision.priority_queue import CorrelationPriorityQueue, ScanTarget
from src.learning.policy_dispatcher import PolicyAutoDispatcher
from src.learning.threshold_tuner import ThresholdConfig, ThresholdTuner
from src.learning.versioned_policy import VersionedPolicy


class DummyTelemetryStore:
    def __init__(self) -> None:
        self.data: dict[str, list[dict]] = {}

    def get_stage_telemetry(self, stage_name: str, limit: int = 10) -> list[dict]:
        return self.data.get(stage_name, [])


class TestPolicyAutoDispatcher(unittest.TestCase):
    def test_generate_and_dispatch_policy(self):
        store = DummyTelemetryStore()
        tuner = ThresholdTuner(
            store=store, config=ThresholdConfig(low_threshold=0.40, medium_threshold=0.55)
        )

        class DummyOptimizer:
            def tag_scores(self):
                return {"sqli": 0.95, "deprecated_tag": 0.10}

            def get_recommended_tags(self):
                return ["sqli", "xss"]

        optimizer = DummyOptimizer()

        dispatcher = PolicyAutoDispatcher(
            threshold_tuner=tuner,
            nuclei_optimizer=optimizer,
        )

        queue = CorrelationPriorityQueue()
        queue.push(
            ScanTarget(
                url="https://example.com/api?tag:sqli", base_priority=5.0, current_priority=5.0
            )
        )
        queue.push(
            ScanTarget(
                url="https://example.com/api?tag:deprecated_tag",
                base_priority=5.0,
                current_priority=5.0,
            )
        )

        policy = dispatcher.generate_policy(
            custom_boosts={"https://example.com/admin": 3.0},
            custom_suppressions={"https://example.com/logout": -4.0},
        )

        self.assertIsInstance(policy, VersionedPolicy)
        self.assertTrue(policy.version.startswith("v1."))
        self.assertIn(("low_threshold", 0.40), policy.threshold_deltas)

        # Dispatch to queue
        applied = dispatcher.dispatch_to_queue(queue, policy)
        self.assertGreaterEqual(applied, 1)

        # Verify boost was applied
        target_sqli = queue._url_map.get("https://example.com/api?tag:sqli")
        self.assertGreater(target_sqli.current_priority, 5.0)

    def test_on_stage_completed_hook(self):
        dispatcher = PolicyAutoDispatcher()
        queue = CorrelationPriorityQueue()
        queue.push(ScanTarget(url="https://example.com/test", base_priority=2.0))

        new_policy = dispatcher.on_stage_completed(
            stage_name="recon",
            telemetry={"fp_rate": 0.05},
            queue=queue,
        )
        self.assertIsNotNone(new_policy)
        self.assertEqual(dispatcher.current_policy, new_policy)
