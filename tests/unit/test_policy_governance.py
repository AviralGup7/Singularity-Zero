"""Unit tests for ML Policy Governance, Shadow Evaluation, and Atomic Rollback."""

from src.learning.policy_governance import PolicyGovernanceGate
from src.learning.versioned_policy import VersionedPolicy


def test_policy_governance_allows_safe_policy() -> None:
    gate = PolicyGovernanceGate(max_boost_multiplier=5.0, max_suppression_pct=0.80)
    policy = VersionedPolicy(
        policy_id="pol_test_1",
        version="1.0.0",
        target_boosts=(("api.example.com", 2.5),),
        target_suppressions=(("static.example.com", 0.1),),
    )

    eval_res = gate.evaluate_candidate(policy)
    assert eval_res.is_safe is True
    assert eval_res.canary_eligible is True

    promoted = gate.promote_policy(policy)
    assert promoted is True
    assert gate.active_policy is not None
    assert gate.active_policy.policy_id == "pol_test_1"


def test_policy_governance_blocks_runaway_boost() -> None:
    gate = PolicyGovernanceGate(max_boost_multiplier=5.0)
    # Dangerous 20.0x boost indicates positive-feedback runaway
    bad_policy = VersionedPolicy(
        policy_id="pol_bad_boost",
        version="2.0.0",
        target_boosts=(("api.example.com", 20.0),),
    )

    eval_res = gate.evaluate_candidate(bad_policy)
    assert eval_res.is_safe is False
    assert any("exceeds limit" in r for r in eval_res.rejection_reasons)

    promoted = gate.promote_policy(bad_policy)
    assert promoted is False


def test_policy_governance_atomic_rollback() -> None:
    gate = PolicyGovernanceGate()
    pol_v1 = VersionedPolicy(
        policy_id="pol_v1",
        version="1.0.0",
        target_boosts=(("target1", 1.5),),
    )
    pol_v2 = VersionedPolicy(
        policy_id="pol_v2",
        version="2.0.0",
        target_boosts=(("target2", 2.0),),
    )

    gate.promote_policy(pol_v1)
    gate.promote_policy(pol_v2)
    assert gate.active_policy.policy_id == "pol_v2"

    rolled_back = gate.rollback()
    assert rolled_back is not None
    assert rolled_back.policy_id == "pol_v1"
    assert gate.active_policy.policy_id == "pol_v1"
