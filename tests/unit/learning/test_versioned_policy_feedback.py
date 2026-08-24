import unittest
from dataclasses import FrozenInstanceError

from src.learning.versioned_policy import VersionedPolicy


class TestVersionedPolicyFeedback(unittest.TestCase):
    def test_versioned_policy_immutability(self):
        policy = VersionedPolicy(
            policy_id="pol_v1",
            version="1.0.0",
            target_boosts=(("https://api.example.com", 25.0),),
            target_suppressions=(("https://example.com/logout", -50.0),),
            threshold_deltas=(("sqli", 0.05),),
        )

        self.assertEqual(policy.policy_id, "pol_v1")
        self.assertEqual(dict(policy.target_boosts)["https://api.example.com"], 25.0)

        # Immutability verification
        with self.assertRaises(FrozenInstanceError):
            policy.version = "2.0.0"  # type: ignore[misc]

        # Serialization roundtrip
        d = policy.to_dict()
        reconstructed = VersionedPolicy.from_dict(d)
        self.assertEqual(reconstructed.policy_id, policy.policy_id)
        self.assertEqual(reconstructed.target_boosts, policy.target_boosts)
