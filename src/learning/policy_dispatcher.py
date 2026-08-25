"""Automated Policy Dispatcher for Closed-Loop Learning Integration.

Coordinates ThresholdTuner, NucleiTagOptimizer, and FeedbackLoop to automatically
generate and dispatch immutable VersionedPolicy snapshots into CorrelationPriorityQueue.
"""

from __future__ import annotations

import logging
import threading
import time
import uuid
from typing import Any

from src.learning.versioned_policy import VersionedPolicy

logger = logging.getLogger(__name__)


class PolicyAutoDispatcher:
    """Orchestrates dynamic calibration signals and dispatches VersionedPolicy to queues."""

    def __init__(
        self,
        threshold_tuner: Any | None = None,
        nuclei_optimizer: Any | None = None,
        feedback_loop: Any | None = None,
        attack_graph_engine: Any | None = None,
    ) -> None:
        self.threshold_tuner = threshold_tuner
        self.nuclei_optimizer = nuclei_optimizer
        self.feedback_loop = feedback_loop
        self.attack_graph_engine = attack_graph_engine
        self._version_seq = 0
        self._current_policy: VersionedPolicy | None = None
        self._lock = threading.RLock()

    @property
    def current_policy(self) -> VersionedPolicy | None:
        with self._lock:
            return self._current_policy

    def generate_policy(
        self,
        custom_boosts: dict[str, float] | None = None,
        custom_suppressions: dict[str, float] | None = None,
        plugin_overrides: dict[str, bool] | None = None,
        attack_chains: list[Any] | None = None,
    ) -> VersionedPolicy:
        """Construct an immutable VersionedPolicy snapshot from active learning and attack graph components."""
        with self._lock:
            self._version_seq += 1
            version_str = f"v{self._version_seq}.{int(time.time())}"
            policy_id = f"pol_{uuid.uuid4().hex[:8]}"

            target_boosts: dict[str, float] = dict(custom_boosts or {})
            target_suppressions: dict[str, float] = dict(custom_suppressions or {})
            threshold_deltas: dict[str, float] = {}
            nuclei_tags: dict[str, Any] = {}

            # 1. Integrate ThresholdTuner updates
            if self.threshold_tuner is not None and hasattr(self.threshold_tuner, "config"):
                cfg = self.threshold_tuner.config
                threshold_deltas["low_threshold"] = getattr(cfg, "low_threshold", 0.45)
                threshold_deltas["medium_threshold"] = getattr(cfg, "medium_threshold", 0.58)
                threshold_deltas["high_threshold"] = getattr(cfg, "high_threshold", 0.72)

            # 2. Integrate NucleiTagOptimizer tags
            if self.nuclei_optimizer is not None:
                if hasattr(self.nuclei_optimizer, "get_recommended_tags"):
                    try:
                        recommended = self.nuclei_optimizer.get_recommended_tags()
                        nuclei_tags["recommended"] = list(recommended)
                    except Exception as exc:
                        logger.debug("PolicyAutoDispatcher: optimizer recommended tags skipped (%s)", exc)
                if hasattr(self.nuclei_optimizer, "tag_scores"):
                    try:
                        scores = self.nuclei_optimizer.tag_scores()
                        nuclei_tags["scores"] = scores
                        for tag, score in scores.items():
                            if score > 0.8:
                                target_boosts[f"tag:{tag}"] = 1.5
                            elif score < 0.2:
                                target_suppressions[f"tag:{tag}"] = -2.0
                    except Exception as exc:
                        logger.debug("PolicyAutoDispatcher: optimizer tag scores skipped (%s)", exc)

            # 3. Integrate FeedbackLoop false positive rules
            if self.feedback_loop is not None and hasattr(self.feedback_loop, "get_suppression_patterns"):
                try:
                    patterns = self.feedback_loop.get_suppression_patterns()
                    for pat in patterns:
                        target_suppressions[pat] = -5.0
                except Exception as exc:
                    logger.debug("PolicyAutoDispatcher: feedback loop patterns skipped (%s)", exc)

            # 4. Integrate AttackGraphEngine multi-hop exploit chain boosts
            chains = attack_chains
            if chains is None and self.attack_graph_engine is not None:
                if hasattr(self.attack_graph_engine, "export_graph"):
                    try:
                        graph_data = self.attack_graph_engine.export_graph()
                        chains = graph_data.get("chains", [])
                    except Exception as exc:
                        logger.debug("PolicyAutoDispatcher: attack graph export skipped (%s)", exc)

            for chain in chains or []:
                entry_id = getattr(chain, "entry_point_id", None) or (chain.get("entry_point_id") if isinstance(chain, dict) else "")
                risk = getattr(chain, "total_risk", None) or (chain.get("total_risk", 1.0) if isinstance(chain, dict) else 1.0)
                if entry_id:
                    url = entry_id.replace("asset:", "")
                    target_boosts[url] = max(target_boosts.get(url, 0.0), float(risk) * 0.5)

            policy = VersionedPolicy(
                policy_id=policy_id,
                version=version_str,
                created_at=time.time(),
                target_boosts=tuple(target_boosts.items()),
                target_suppressions=tuple(target_suppressions.items()),
                plugin_overrides=tuple((plugin_overrides or {}).items()),
                threshold_deltas=tuple(threshold_deltas.items()),
                nuclei_adaptive_tags=tuple(nuclei_tags.items()),
            )
            self._current_policy = policy
            return policy

    def dispatch_to_queue(
        self,
        queue: Any,
        policy: VersionedPolicy | None = None,
    ) -> int:
        """Apply a generated or provided policy to CorrelationPriorityQueue."""
        with self._lock:
            target_policy = policy or self._current_policy or self.generate_policy()
            if hasattr(queue, "apply_versioned_policy"):
                return queue.apply_versioned_policy(target_policy)
            return 0

    def on_stage_completed(
        self,
        stage_name: str,
        telemetry: dict[str, Any] | None = None,
        queue: Any | None = None,
    ) -> VersionedPolicy:
        """Hook called at stage boundary to auto-calibrate and dispatch updated policy."""
        with self._lock:
            # Calibrate threshold tuner if telemetry provided
            if self.threshold_tuner is not None and telemetry:
                if hasattr(self.threshold_tuner, "update_from_stage"):
                    try:
                        self.threshold_tuner.update_from_stage(stage_name, telemetry)
                    except Exception as exc:
                        logger.debug("PolicyAutoDispatcher: threshold tuner stage update skipped (%s)", exc)

            new_policy = self.generate_policy()
            if queue is not None:
                self.dispatch_to_queue(queue, new_policy)
            return new_policy


__all__ = ["PolicyAutoDispatcher"]
