"""WAF detection and bypass package.

Public surface:

* :func:`fingerprint_response` — returns the best WAF/CDN candidate.
* :func:`detect_challenge` — classifies a response as a challenge page.
* :func:`build_strategy_bundle` — picks payloads tailored to a WAF.
* :func:`smuggling_probes` — returns CL.TE / TE.CL / TE.TE / H2 probes.
"""

from __future__ import annotations

from src.detection.waf.challenge import (
    ChallengeAssessment,
    assess_for_engine,
    detect_challenge,
    is_challenge_response,
)
from src.detection.waf.fingerprint import (
    WAFMatch,
    fingerprint_response,
    fingerprint_to_finding,
    identify_candidates,
)
from src.detection.waf.fingerprints import (
    CATALOGUE,
    STRATEGY_DESCRIPTIONS,
    WAFFingerprint,
)
from src.detection.waf.strategies import (
    SmugglingProbe,
    StrategyBundle,
    build_strategy_bundle,
    case_swap,
    comment_injection_html,
    comment_injection_sql,
    double_encode,
    double_encode_path,
    double_encode_query_param,
    h2_header_lowercase_split,
    h2_pseudo_path_smuggle,
    json_pad,
    payloads_for,
    smuggling_probes,
    unicode_normalize,
)
from src.detection.waf.strategies import (
    describe_strategy as _describe_via_fingerprints,
)
from src.detection.waf.hmm_evader import HMMWafEvader

__all__ = [
    "CATALOGUE",
    "ChallengeAssessment",
    "HMMWafEvader",
    "SmugglingProbe",
    "STRATEGY_DESCRIPTIONS",
    "StrategyBundle",
    "WAFMatch",
    "WAFFingerprint",
    "assess_for_engine",
    "build_strategy_bundle",
    "case_swap",
    "comment_injection_html",
    "comment_injection_sql",
    "detect_challenge",
    "double_encode",
    "double_encode_path",
    "double_encode_query_param",
    "fingerprint_response",
    "fingerprint_to_finding",
    "h2_header_lowercase_split",
    "h2_pseudo_path_smuggle",
    "identify_candidates",
    "is_challenge_response",
    "json_pad",
    "payloads_for",
    "smuggling_probes",
    "unicode_normalize",
]


def describe_strategy(name: str) -> str:
    return _describe_via_fingerprints(name)
