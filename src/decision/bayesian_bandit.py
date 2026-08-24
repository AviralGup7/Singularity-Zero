"""Bayesian Multi-Armed Bandit & Pareto Frontier target scheduler.

Implements online Bayesian parameter density estimation using Beta-Binomial
conjugates and Thompson Sampling, combined with Upper Confidence Bound (UCB1)
exploration and Pareto-optimal multi-objective dispatch.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass, field
from typing import Any


@dataclass
class BetaBinomialArm:
    """Conjugate Beta prior for Bernoulli vulnerability discovery probability."""

    alpha: float = 1.0  # Prior successes (findings)
    beta_param: float = 3.0  # Prior failures (clean scans)
    pulls: int = 0
    successes: int = 0

    def sample_thompson(self, rng: random.Random | None = None) -> float:
        """Draw a sample from the posterior Beta distribution using random.betavariate."""
        r = rng or random
        return r.betavariate(max(0.001, self.alpha), max(0.001, self.beta_param))

    def expected_value(self) -> float:
        """Mean of posterior distribution."""
        return self.alpha / (self.alpha + self.beta_param)

    def ucb1_score(self, total_pulls: int, c: float = 1.414) -> float:
        """Upper Confidence Bound (UCB1) score balancing mean and exploration bonus."""
        if self.pulls == 0:
            return 100.0  # High bonus for unvisited arms to guarantee initial exploration
        mean = self.expected_value()
        exploration = c * math.sqrt(math.log(max(1, total_pulls)) / self.pulls)
        return mean + exploration

    def record_outcome(self, found_vulnerability: bool, weight: float = 1.0) -> None:
        """Update posterior with online Bayesian conjugate update."""
        self.pulls += 1
        if found_vulnerability:
            self.successes += 1
            self.alpha += weight
        else:
            self.beta_param += weight


class BayesianParameterBandit:
    """Maintains parameter archetype arms and selects optimal targets via Thompson Sampling."""

    def __init__(self) -> None:
        self._arms: dict[str, BetaBinomialArm] = {}
        self._total_pulls: int = 0

    def get_or_create_arm(self, archetype: str) -> BetaBinomialArm:
        if archetype not in self._arms:
            self._arms[archetype] = BetaBinomialArm()
        return self._arms[archetype]

    def score_target(
        self,
        archetypes: list[str],
        base_priority: float,
        use_thompson: bool = True,
        rng: random.Random | None = None,
    ) -> float:
        """Compute Bayesian dispatch score for a target given its parameter archetypes."""
        if not archetypes:
            return max(1.0, base_priority)

        arm_scores = []
        for arch in archetypes:
            arm = self.get_or_create_arm(arch)
            if use_thompson:
                sample = arm.sample_thompson(rng)
            else:
                sample = arm.ucb1_score(self._total_pulls)
            arm_scores.append(sample)

        avg_sample = sum(arm_scores) / len(arm_scores)
        # Combine base target criticality with Bayesian posterior multiplier
        return base_priority * (1.0 + (avg_sample * 4.0))

    def update(self, archetypes: list[str], found_vulnerability: bool, weight: float = 1.0) -> None:
        """Update Bayesian arms based on scan observation."""
        self._total_pulls += 1
        for arch in archetypes:
            arm = self.get_or_create_arm(arch)
            arm.record_outcome(found_vulnerability, weight)


@dataclass(frozen=True, slots=True)
class ParetoObjective:
    """Multi-dimensional performance and yield metrics for a target."""

    exploitability: float  # 0.0 - 10.0
    business_impact: float  # 0.0 - 10.0
    latency_cost_ms: float  # Latency penalty
    bayesian_prob: float  # P(vuln) from Bandit

    def pareto_score(self) -> float:
        """Calculate scalarized Pareto score optimizing yield per unit latency."""
        eff_latency = max(50.0, self.latency_cost_ms)
        numerator = (self.exploitability * 0.4 + self.business_impact * 0.6) * (1.0 + self.bayesian_prob * 3.0)
        return (numerator / eff_latency) * 1000.0


__all__ = [
    "BayesianParameterBandit",
    "BetaBinomialArm",
    "ParetoObjective",
]
