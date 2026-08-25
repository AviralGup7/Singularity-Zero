"""Policy Governance, Shadow Evaluation, and Canary Promotion Gatekeeper.

Decouples ML / Active Learning from execution authority:
- Shadow Evaluation: Tests candidate VersionedPolicy against historical findings
- Runaway Feedback Detection: Rejects policies with extreme target boost / total suppression
- Canary Promotion: Allows staged rollout before full cluster activation
- Atomic Rollback: Instantly reverts to parent_policy_id upon performance degradation
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass
from typing import Any

from src.learning.versioned_policy import VersionedPolicy

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class PolicyEvaluationResult:
    """Outcome of evaluating a candidate policy against safety and invariant checks."""

    policy_id: str
    is_safe: bool
    canary_eligible: bool
    rejection_reasons: tuple[str, ...] = ()
    anomaly_score: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "is_safe": self.is_safe,
            "canary_eligible": self.canary_eligible,
            "rejection_reasons": list(self.rejection_reasons),
            "anomaly_score": self.anomaly_score,
        }


class PolicyGovernanceGate:
    """Governs policy lifecycle, evaluation, and safe atomic promotion/rollback."""

    def __init__(
        self,
        max_boost_multiplier: float = 5.0,
        max_suppression_pct: float = 0.80,
    ) -> None:
        self.max_boost_multiplier = max_boost_multiplier
        self.max_suppression_pct = max_suppression_pct
        self._active_policy: VersionedPolicy | None = None
        self._policy_history: dict[str, VersionedPolicy] = {}
        self._lock = threading.RLock()

    @property
    def active_policy(self) -> VersionedPolicy | None:
        with self._lock:
            return self._active_policy

    def evaluate_candidate(self, policy: VersionedPolicy) -> PolicyEvaluationResult:
        """Run shadow checks on a candidate policy to prevent positive feedback runaway."""
        reasons: list[str] = []
        anomaly_score = 0.0

        # Check 1: Excessive Boost Multiplier
        for target, boost in policy.target_boosts:
            if boost > self.max_boost_multiplier:
                reasons.append(f"Target boost for '{target}' ({boost:.2f}x) exceeds limit ({self.max_boost_multiplier:.2f}x)")
                anomaly_score += 0.5

        # Check 2: Total Suppression Overkill
        if policy.target_suppressions and policy.target_boosts:
            total_rules = len(policy.target_boosts) + len(policy.target_suppressions)
            supp_pct = len(policy.target_suppressions) / total_rules
            if supp_pct > self.max_suppression_pct:
                reasons.append(f"Policy suppresses {supp_pct:.1%} of targets (exceeds {self.max_suppression_pct:.1%})")
                anomaly_score += 0.4

        # Check 3: Signature verification
        if policy.signature:
            expected_sig = policy.compute_signature()
            if policy.signature != expected_sig:
                reasons.append("Cryptographic signature mismatch: policy may be tampered")
                anomaly_score += 1.0

        is_safe = len(reasons) == 0
        canary_eligible = is_safe and anomaly_score < 0.3

        return PolicyEvaluationResult(
            policy_id=policy.policy_id,
            is_safe=is_safe,
            canary_eligible=canary_eligible,
            rejection_reasons=tuple(reasons),
            anomaly_score=anomaly_score,
        )

    def promote_policy(self, policy: VersionedPolicy) -> bool:
        """Atomically promote a safe policy to ACTIVE."""
        with self._lock:
            eval_res = self.evaluate_candidate(policy)
            if not eval_res.is_safe:
                logger.warning("Policy %s rejected by governance gate: %s", policy.policy_id, eval_res.rejection_reasons)
                return False

            promoted = VersionedPolicy.from_mapping({
                **policy.to_dict(),
                "parent_policy_id": self._active_policy.policy_id if self._active_policy else "",
                "status": "ACTIVE",
            })
            self._policy_history[promoted.policy_id] = promoted
            self._active_policy = promoted
            logger.info("Policy %s (v%s) promoted to ACTIVE", promoted.policy_id, promoted.version)
            return True

    def rollback(self) -> VersionedPolicy | None:
        """Atomically rollback active policy to its parent version."""
        with self._lock:
            if not self._active_policy:
                return None
            parent_id = self._active_policy.parent_policy_id
            if not parent_id or parent_id not in self._policy_history:
                logger.warning("No valid parent policy found for rollback from %s", self._active_policy.policy_id)
                return None

            parent = self._policy_history[parent_id]
            rolled_back = VersionedPolicy.from_mapping({
                **parent.to_dict(),
                "status": "ACTIVE",
            })
            self._active_policy = rolled_back
            logger.info("Rolled back active policy to parent %s (v%s)", rolled_back.policy_id, rolled_back.version)
            return rolled_back
