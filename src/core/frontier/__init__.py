"""Frontier module - distributed state and evasion components."""

from src.core.frontier.chameleon import RequestChameleon, wrap_polymorphic_request
from src.core.frontier.chameleon_evasion import (
    ChameleonEvasionEngine,
    JA3FingerprintModel,
    PPOEvasionModel,
    TimingPermutator,
)

__all__ = [
    "ChameleonEvasionEngine",
    "PPOEvasionModel",
    "JA3FingerprintModel",
    "RequestChameleon",
    "TimingPermutator",
    "wrap_polymorphic_request",
]
