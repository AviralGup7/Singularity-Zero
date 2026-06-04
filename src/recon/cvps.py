"""Contextual Vulnerability Priority Scoring (CVPS) Engine.

Computes a context-aware priority score for endpoints by assessing query parameters,
exposed ports, data sensitivity, and overall application profile attributes.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

# Parameters containing highly sensitive or critical data vectors.
# Use a leading boundary only (start-of-string, ``_``, or non-word) and allow
# the keyword to be followed by additional word characters. The previous
# pattern required BOTH leading AND trailing boundaries, so a parameter
# named ``password`` matched only ``pass`` (no boundary after ``s``) and
# was missed entirely.
_SENSITIVE_PARAM_RE = re.compile(
    r"(?:^|[^A-Za-z0-9])(?:ssn|card|credit|pass(?:word|wd)?|pwd|secret|token|auth|api[_-]?key|key|admin|priv|salary|billing|invoice|uuid)\w*",
    re.IGNORECASE,
)


def compute_cvps_score(
    url: str, port: int = 443, context_profile: dict[str, Any] | None = None
) -> float:
    """Calculate the Contextual Vulnerability Priority Score (CVPS) for a URL.

    Args:
        url: The endpoint URL to analyze.
        port: The service port running the host endpoint.
        context_profile: Target profiling attributes (api_heavy, auth_heavy, etc.)

    Returns:
        A contextual float score boost to prioritize scanner scheduling.
    """
    score_boost = 0.0
    parsed = urlparse(url)
    path = parsed.path.lower()
    query = parsed.query.lower()
    profile = context_profile or {}

    # 1. Parameter Sensitivity Checking
    if _SENSITIVE_PARAM_RE.search(query) or _SENSITIVE_PARAM_RE.search(path):
        score_boost += 8.5

    # 2. Port exposure risks
    if port not in {80, 443}:
        # Non-standard ports (e.g. 8080, 8443, 9000) indicate microservices or admin panels
        score_boost += 4.0
        if port in {8080, 8443, 9000, 9443}:
            score_boost += 2.5

    # 3. Target profile heavy alignment bonuses
    if profile.get("api_heavy", False) and any(
        t in path for t in {"/api/", "/v1/", "/v2/", "/v3/"}
    ):
        score_boost += 3.5
    if profile.get("auth_heavy", False) and any(
        t in path for t in {"login", "auth", "token", "session"}
    ):
        score_boost += 4.5
    if profile.get("file_heavy", False) and any(
        t in path for t in {"upload", "download", "file", "export"}
    ):
        score_boost += 3.0

    return round(score_boost, 2)
