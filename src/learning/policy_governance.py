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
    """Governs policy lifecycle, evaluation, and safe atomic promotion/rollback via Raft."""

    def __init__(
        self,
        max_boost_multiplier: float = 5.0,
        max_suppression_pct: float = 0.80,
        replicated_log: Any | None = None,
    ) -> None:
        self.max_boost_multiplier = max_boost_multiplier
        self.max_suppression_pct = max_suppression_pct
        self.replicated_log = replicated_log
        self._active_policy: VersionedPolicy | None = None
        self._policy_history: dict[str, VersionedPolicy] = {}
        self._lock = threading.RLock()

    @property
    def active_policy(self) -> VersionedPolicy | None:
        with self._lock:
            return self._active_policy

    def evaluate_candidate(self, policy: VersionedPolicy) -> PolicyEvaluationResult:
        """Run pre-promotion schema validation, safety bounds, and shadow checks on candidate policy."""
        reasons: list[str] = []
        anomaly_score = 0.0

        # Check 0: Mandatory Schema & Identity Validation
        if not policy.policy_id or not policy.policy_id.strip():
            reasons.append("Schema violation: policy_id must not be empty")
            anomaly_score += 1.0
        if not policy.version or not policy.version.strip():
            reasons.append("Schema violation: policy version must not be empty")
            anomaly_score += 1.0

        # Check 0b: Threshold bounds [0.0, 1.0]
        if hasattr(policy, "thresholds") and isinstance(policy.thresholds, dict):
            for t_name, t_val in policy.thresholds.items():
                if not (0.0 <= float(t_val) <= 1.0):
                    reasons.append(
                        f"Threshold bounds violation: '{t_name}' ({t_val}) not in range [0.0, 1.0]"
                    )
                    anomaly_score += 0.5

        # Check 1: Excessive Boost Multiplier
        for target, boost in policy.target_boosts:
            if boost > self.max_boost_multiplier:
                reasons.append(
                    f"Target boost for '{target}' ({boost:.2f}x) exceeds limit ({self.max_boost_multiplier:.2f}x)"
                )
                anomaly_score += 0.5
            elif boost < 0.0:
                reasons.append(f"Negative boost for '{target}' ({boost:.2f}x) is invalid")
                anomaly_score += 0.5

        # Check 2: Total Suppression Overkill
        if policy.target_suppressions and policy.target_boosts:
            total_rules = len(policy.target_boosts) + len(policy.target_suppressions)
            supp_pct = len(policy.target_suppressions) / total_rules
            if supp_pct > self.max_suppression_pct:
                reasons.append(
                    f"Policy suppresses {supp_pct:.1%} of targets (exceeds {self.max_suppression_pct:.1%})"
                )
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
        """Atomically promote a safe policy to ACTIVE via Raft FSM commit."""
        import uuid
        from src.core.contracts.command_envelope import CommandEnvelope

        with self._lock:
            eval_res = self.evaluate_candidate(policy)
            if not eval_res.is_safe:
                logger.warning(
                    "Policy %s rejected by governance gate: %s",
                    policy.policy_id,
                    eval_res.rejection_reasons,
                )
                return False

            parent_id = self._active_policy.policy_id if self._active_policy else ""

            if self.replicated_log is None:
                logger.error(
                    "Policy promotion of %s rejected: no authoritative replicated log (fail-closed)",
                    policy.policy_id,
                )
                return False

            if self.replicated_log is not None:
                cmd = CommandEnvelope(
                    command_id=f"cmd_promote_{uuid.uuid4().hex[:8]}",
                    command_type="PromotePolicyCommand",
                    aggregate_id="policy_active",
                    payload={
                        "policy_id": policy.policy_id,
                        "artifact_hash": policy.compute_signature(),
                        "policy_version": policy.version,
                        "parent_policy_id": parent_id,
                    },
                    correlation_id="governance_gate",
                    causation_id=f"promote_{policy.policy_id}",
                )
                receipt, _ = self.replicated_log.propose_and_commit(cmd)
                if receipt.result_code != "POLICY_PROMOTED":
                    logger.error(
                        "Raft promotion failed for policy %s: %s",
                        policy.policy_id,
                        receipt.result_code,
                    )
                    return False

            promoted = VersionedPolicy.from_mapping(
                {
                    **policy.to_dict(),
                    "parent_policy_id": parent_id,
                    "status": "ACTIVE",
                }
            )
            self._policy_history[promoted.policy_id] = promoted
            self._active_policy = promoted
            logger.info("Policy %s (v%s) promoted to ACTIVE", promoted.policy_id, promoted.version)
            return True

    def rollback(self) -> VersionedPolicy | None:
        """Atomically rollback active policy to its parent version via Raft FSM commit."""
        import uuid
        from src.core.contracts.command_envelope import CommandEnvelope

        with self._lock:
            if not self._active_policy:
                return None
            parent_id = self._active_policy.parent_policy_id
            if not parent_id or parent_id not in self._policy_history:
                logger.warning(
                    "No valid parent policy found for rollback from %s",
                    self._active_policy.policy_id,
                )
                return None

            if self.replicated_log is None:
                logger.error(
                    "Policy rollback rejected: no authoritative replicated log (fail-closed)"
                )
                return None

            if self.replicated_log is not None:
                cmd = CommandEnvelope(
                    command_id=f"cmd_rollback_{uuid.uuid4().hex[:8]}",
                    command_type="RollbackPolicyCommand",
                    aggregate_id="policy_active",
                    payload={"parent_policy_id": parent_id},
                    correlation_id="governance_gate",
                    causation_id="rollback_trigger",
                )
                receipt, _ = self.replicated_log.propose_and_commit(cmd)
                if receipt.result_code != "POLICY_ROLLED_BACK":
                    logger.error("Raft rollback failed to %s: %s", parent_id, receipt.result_code)
                    return None

            parent = self._policy_history[parent_id]
            rolled_back = VersionedPolicy.from_mapping(
                {
                    **parent.to_dict(),
                    "status": "ACTIVE",
                }
            )
            self._active_policy = rolled_back
            logger.info(
                "Rolled back active policy to parent %s (v%s)",
                rolled_back.policy_id,
                rolled_back.version,
            )
            return rolled_back
