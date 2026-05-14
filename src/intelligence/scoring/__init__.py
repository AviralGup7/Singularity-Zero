"""Intelligence-based risk scoring.

Re-exports from analysis for backward compatibility while adding
intelligence-layer-specific scoring operations that combine
threat intelligence, endpoint behavior, and finding correlation.
"""

from src.analysis.behavior.payment import (
    payment_flow_intelligence,
    payment_provider_detection,
)
from src.analysis.intelligence.endpoint.endpoint_intelligence import (
    build_endpoint_intelligence,
)
from src.intelligence.scoring.risk_scoring import (
    aggregate_risk_profile,
    calculate_intelligence_risk,
    score_endpoint_exposure,
)

__all__ = [
    # Re-exports from analysis
    "build_endpoint_intelligence",
    "payment_flow_intelligence",
    "payment_provider_detection",
    # Intelligence-layer additions
    "calculate_intelligence_risk",
    "score_endpoint_exposure",
    "aggregate_risk_profile",
]
