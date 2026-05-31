"""
Deep Reinforcement Learning (DRL) for Polymorphic Evasion

Implements a lightweight Proximal Policy Optimization (PPO) model
for evasion state transitions. It replaces the HMMEvasionModel.
"""

from __future__ import annotations

import math
import random
from typing import Any

from src.core.logging.trace_logging import get_pipeline_logger

logger = get_pipeline_logger(__name__)


class TelemetrySink:
    def emit(
        self,
        model_id: str,
        weight_drift: float,
        l2_norm: float,
        action_distribution: list[float],
    ) -> None:
        pass


_telemetry_sink = TelemetrySink()


def set_telemetry_sink(sink: Any) -> None:
    global _telemetry_sink
    if sink is None or not callable(getattr(sink, "emit", None)):
        _telemetry_sink = TelemetrySink()
        return
    _telemetry_sink = sink


class PPOEvasionModel:
    """
    Proximal Policy Optimization (PPO) agent for WAF evasion.
    Treats delays, JA3 fingerprints, and HTTP/2 headers as an action space.
    Replaces HMMEvasionModel.
    """

    STATE_UNDETECTED = 0
    STATE_SUSPECTED = 1
    STATE_BLOCKED = 2
    STATE_EVADING = 3

    OBS_SUCCESS = 0
    OBS_CHALLENGE = 1
    OBS_BLOCK = 2
    OBS_RATE_LIMIT = 3
    _VALID_OBSERVATIONS = frozenset((OBS_SUCCESS, OBS_CHALLENGE, OBS_BLOCK, OBS_RATE_LIMIT))
    _VALID_STATES = frozenset((STATE_UNDETECTED, STATE_SUSPECTED, STATE_BLOCKED, STATE_EVADING))
    _MAX_OBS_HISTORY = 256
    _MAX_WEIGHT = 10.0

    def __init__(self, learning_rate: float = 0.5, gamma: float = 0.99):
        self._current_state = self.STATE_UNDETECTED
        self._learning_rate = min(max(float(learning_rate), 0.0), 1.0)
        self._gamma = min(max(float(gamma), 0.0), 1.0)
        self._action_space_size = 4
        self._obs_history: list[int] = []
        self._model_id = f"ppo-evader-{id(self)}"
        self._rng = random.SystemRandom()

        # Simple Neural Network Weights for Policy (Action Probabilities)
        # Input: 4-dim (one-hot observation), Hidden: 8, Output: 4
        self._w1 = [[self._rng.uniform(-0.1, 0.1) for _ in range(8)] for _ in range(4)]
        self._w2 = [[self._rng.uniform(-0.1, 0.1) for _ in range(4)] for _ in range(8)]

        # Bias the network to behave reasonably immediately
        for i in range(4):
            # Map input i to hidden i, and hidden i to output i
            self._w1[i][i] = 2.0
            self._w2[i][i] = 2.0

        self._last_action = self.STATE_UNDETECTED
        self._last_obs_vector = [1.0, 0.0, 0.0, 0.0]

    def _forward(self, obs_vector: list[float]) -> tuple[list[float], list[float]]:
        if len(obs_vector) != self._action_space_size:
            obs_vector = [1.0, 0.0, 0.0, 0.0]
        obs_vector = [v if math.isfinite(v) else 0.0 for v in obs_vector]

        # Hidden layer
        hidden = [0.0] * 8
        for i in range(8):
            for j in range(4):
                hidden[i] += obs_vector[j] * self._w1[j][i]
            # ReLU
            hidden[i] = min(max(0.0, hidden[i]), self._MAX_WEIGHT)

        # Output layer
        out = [0.0] * 4
        for i in range(4):
            for j in range(8):
                out[i] += hidden[j] * self._w2[j][i]

        # Softmax
        out = [o if math.isfinite(o) else 0.0 for o in out]
        max_out = max(out)
        exp_out = [math.exp(o - max_out) for o in out]
        sum_exp = sum(exp_out)
        if not math.isfinite(sum_exp) or sum_exp <= 0.0:
            return hidden, [0.25, 0.25, 0.25, 0.25]
        probs = [e / sum_exp for e in exp_out]

        return hidden, probs

    def observe(self, observation: int) -> None:
        """Update model based on observed response and compute reward."""
        if observation not in self._VALID_OBSERVATIONS:
            raise ValueError(f"invalid PPO observation: {observation!r}")
        if self._current_state not in self._VALID_STATES:
            logger.warning("Resetting corrupted PPO state %r to undetected", self._current_state)
            self._current_state = self.STATE_UNDETECTED
            self._last_action = self.STATE_UNDETECTED

        self._obs_history.append(observation)
        if len(self._obs_history) > self._MAX_OBS_HISTORY:
            del self._obs_history[: -self._MAX_OBS_HISTORY]

        # Define reward based on observation
        reward = 0.0
        if observation == self.OBS_SUCCESS:
            reward = 1.0
        elif observation == self.OBS_CHALLENGE:
            reward = -0.5
        elif observation == self.OBS_BLOCK:
            reward = -1.0
        elif observation == self.OBS_RATE_LIMIT:
            reward = -0.8

        # Policy Gradient Update (simplified PPO/REINFORCE step)
        # In a full PPO we'd store trajectories and optimize surrogate objective.
        # Here we do a step of online policy gradient for the prototype.
        hidden, probs = self._forward(self._last_obs_vector)

        # Track previous weights to compute drift
        prev_w2 = [row[:] for row in self._w2]

        # Gradient of log prob
        d_out = [0.0] * 4
        for i in range(4):
            if i == self._last_action:
                d_out[i] = (1.0 - probs[i]) * reward * self._learning_rate
            else:
                d_out[i] = (0.0 - probs[i]) * reward * self._learning_rate

        # Backprop to W2
        for j in range(8):
            for i in range(4):
                self._w2[j][i] = self._clamp_weight(self._w2[j][i] + hidden[j] * d_out[i])

        # Backprop to W1
        d_hidden = [0.0] * 8
        for j in range(8):
            for i in range(4):
                d_hidden[j] += d_out[i] * prev_w2[j][i]
            # ReLU derivative
            if hidden[j] <= 0:
                d_hidden[j] = 0

        for k in range(4):
            for j in range(8):
                self._w1[k][j] = self._clamp_weight(
                    self._w1[k][j] + self._last_obs_vector[k] * d_hidden[j]
                )

        # Prepare for next action selection
        new_obs_vector = [0.0] * 4
        new_obs_vector[observation] = 1.0
        self._last_obs_vector = new_obs_vector

        # Update current state conceptually
        self.get_evasion_action()

        # Telemetry Emission
        weight_drift = sum(abs(self._w2[j][i] - prev_w2[j][i]) for j in range(8) for i in range(4))
        l2_norm = sum(w**2 for row in self._w2 for w in row) ** 0.5
        _, new_probs = self._forward(self._last_obs_vector)
        try:
            _telemetry_sink.emit(self._model_id, weight_drift, l2_norm, new_probs)
        except Exception as exc:
            logger.debug("PPO telemetry emission skipped: %s", exc)

    def _clamp_weight(self, value: float) -> float:
        if not math.isfinite(value):
            return 0.0
        return min(max(value, -self._MAX_WEIGHT), self._MAX_WEIGHT)

    def get_evasion_action(self) -> dict[str, Any]:
        """Return recommended evasion action based on NN output."""
        _, probs = self._forward(self._last_obs_vector)
        # Zero out probability of STATE_UNDETECTED if block/challenge/rate limit is active
        if (
            self._last_obs_vector[self.OBS_BLOCK] == 1.0
            or self._last_obs_vector[self.OBS_CHALLENGE] == 1.0
            or self._last_obs_vector[self.OBS_RATE_LIMIT] == 1.0
        ):
            probs[self.STATE_UNDETECTED] = 0.0
            # Renormalize
            s = sum(probs)
            if s > 0:
                probs = [p / s for p in probs]
            else:
                probs = [0.0, 0.33, 0.33, 0.34]

        # Greedy selection (argmax) for stable state transition during execution
        action = probs.index(max(probs))

        self._last_action = action
        self._current_state = action  # Bind state conceptually to the action taken

        # Construct continuous-like action space based on the discrete output
        # to interface seamlessly with existing components.
        actions = {
            self.STATE_UNDETECTED: {
                "intensity": "low",
                "delay_ms": self._rng.randint(50, 200),
                "header_mutate": False,
                "ja3_profile": None,
            },
            self.STATE_SUSPECTED: {
                "intensity": "medium",
                "delay_ms": self._rng.randint(300, 700),
                "header_mutate": True,
                "ja3_profile": "chrome_windows",
            },
            self.STATE_BLOCKED: {
                "intensity": "high",
                "delay_ms": self._rng.randint(1000, 2000),
                "header_mutate": True,
                "ja3_profile": "firefox_windows",
            },
            self.STATE_EVADING: {
                "intensity": "maximum",
                "delay_ms": self._rng.randint(2500, 4000),
                "header_mutate": True,
                "ja3_profile": "safari_macos",
            },
        }
        return actions.get(self._current_state, actions[self.STATE_UNDETECTED])

    def get_current_state(self) -> int:
        return self._current_state

    def get_state_name(self, state: int | None = None) -> str:
        s = state if state is not None else self._current_state
        names = {
            self.STATE_UNDETECTED: "undetected",
            self.STATE_SUSPECTED: "suspected",
            self.STATE_BLOCKED: "blocked",
            self.STATE_EVADING: "evading",
        }
        return names.get(s, "unknown")
