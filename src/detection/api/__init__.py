"""API-specific detection layer.

The API surface area covered by this package was previously missing from
the detection stack. The five gaps closed here are:

* :mod:`src.detection.api.rest_param_pollution` — REST parameter pollution
  (HPP) where repeated query/body parameters bind inconsistently
  (``?a=1&a=2`` vs array binding vs last-write-wins).
* :mod:`src.detection.api.graphql_introspection` — GraphQL introspection
  query detection (presence in URL, body, custom headers, GraphiQL UI,
  persisted/disabled introspection).
* :mod:`src.detection.api.rate_limit_diff` — per-endpoint rate-limiting
  delta detection (different limits across endpoints, missing limits on
  high-cost routes, inconsistent presence of rate-limit headers).
* :mod:`src.detection.api.jwt_claim_integrity` — JWT claim manipulation
  detection (``alg=none``, algorithm confusion, missing ``kid``/``typ``
  validation, signature stripping, header injection points).
* :mod:`src.detection.api.websocket_message_security` — WebSocket
  message-level injection surface and subprotocol / origin validation
  gaps.

All five submodules expose pure-data analysis helpers and follow the
``DetectionFinding``/dict shape used by the rest of the detection layer
so they slot into :mod:`src.detection.handlers` without glue code.
"""

from __future__ import annotations

from src.detection.api.graphql_introspection import (
    GraphQLIntrospectionFinding,
    analyze_graphql_introspection,
    graphql_introspection_findings_from_observations,
)
from src.detection.api.jwt_claim_integrity import (
    JWTClaimIntegrityFinding,
    analyze_jwt_claim_integrity,
    jwt_claim_findings_from_observations,
)
from src.detection.api.rate_limit_diff import (
    RateLimitEndpointObservation,
    RateLimitEndpointProfile,
    build_endpoint_profiles,
    endpoint_profiles_to_findings,
)
from src.detection.api.rest_param_pollution import (
    RestParamPollutionFinding,
    analyze_rest_parameter_pollution,
    rest_param_pollution_findings_from_observations,
)
from src.detection.api.websocket_message_security import (
    WebSocketMessageSecurityFinding,
    analyze_websocket_message_security,
    websocket_message_findings_from_observations,
)

__all__ = [
    "GraphQLIntrospectionFinding",
    "JWTClaimIntegrityFinding",
    "RateLimitEndpointObservation",
    "RateLimitEndpointProfile",
    "RestParamPollutionFinding",
    "WebSocketMessageSecurityFinding",
    "analyze_graphql_introspection",
    "analyze_jwt_claim_integrity",
    "analyze_rest_parameter_pollution",
    "analyze_websocket_message_security",
    "build_endpoint_profiles",
    "endpoint_profiles_to_findings",
    "graphql_introspection_findings_from_observations",
    "jwt_claim_findings_from_observations",
    "rest_param_pollution_findings_from_observations",
    "websocket_message_findings_from_observations",
]
