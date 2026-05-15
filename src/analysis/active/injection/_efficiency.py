"""Reflection efficiency scoring for active probe responses.

Measures how well a test marker or payload is reflected in an HTTP response.
Inspired by XSStrike's checker.py (fuzzy matching on reflection efficiency)
but uses standard library only.

The key insight: not all reflections are equal. A fully intact reflection
(100% efficiency) means no filtering is occurring. A partial reflection
indicates sanitization or escaping. No reflection means the payload was
blocked or filtered entirely.
"""

from __future__ import annotations


def reflection_efficiency(response_text: str, marker: str) -> int:
    """Score 0-100 how completely the marker is reflected in the response.

    Uses a character-sequence matching approach (similar to fuzzy ratio
    but without external dependencies) to determine what percentage of
    the marker survives in the response.

    Args:
        response_text: The full HTTP response body (lowercase recommended).
        marker: The original test marker string.

    Returns:
        Efficiency score 0-100.
    """
    if not marker:
        return 0

    marker_lower = marker.lower()
    response_lower = response_text.lower()

    # Exact match = 100
    if marker_lower in response_lower:
        # Check for exact case match as bonus indicator
        if marker in response_text:
            return 100
        # Case-altered but intact = 95
        return 95

    # Check for common escape patterns
    escaped = _check_escaped(response_text, marker)
    if escaped >= 0:
        return escaped

    # Check for partial reflection using character sequence matching
    return _partial_ratio(response_lower, marker_lower)


def _check_escaped(response_text: str, marker: str) -> int:
    """Check if the marker is reflected but with escape characters."""
    # HTML entity encoding
    html_encoded = (
        marker.replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("&", "&amp;")
        .replace('"', "&quot;")
        .replace("'", "&#x27;")
    )
    if html_encoded in response_text:
        return 85

    # URL encoding
    try:
        from urllib.parse import quote

        url_encoded = quote(marker, safe="")
        if url_encoded in response_text or url_encoded.lower() in response_text.lower():
            return 80
    except Exception:
        pass

    # Backslash escaping
    escaped = "\\" + marker
    if escaped in response_text:
        return 70

    # Double encoding
    double_encoded = html_encoded.replace("&", "&amp;")
    if double_encoded in response_text:
        return 75

    return -1


def _partial_ratio(response_lower: str, marker_lower: str) -> int:
    """Character-sequence partial ratio (inspired by fuzzywuzzy partial_ratio).

    Finds the best alignment of the marker within the response and returns
    a percentage of how much of the marker is found in the best window.

    Uses longest common subsequence as a fallback when direct substring
    matching fails.
    """
    marker_len = len(marker_lower)
    if marker_len == 0:
        return 0

    len(response_lower)

    # Check if any consecutive character block of the marker appears
    best_run = _longest_consecutive_run(response_lower, marker_lower)
    if best_run >= marker_len * 0.7:
        # 70%+ consecutive chars found
        return round(best_run / marker_len * 100)

    # Fallback: character coverage
    marker_chars = set(marker_lower)
    response_chars = set(response_lower)
    common = marker_chars & response_chars

    if len(marker_chars) == 0:
        return 0

    coverage = len(common) / len(marker_chars)
    if coverage < 0.5:
        return 0

    # Scale coverage to 0-60 (partial matches are low confidence)
    return round(coverage * 60)


def _longest_consecutive_run(haystack: str, needle: str) -> int:
    """Find the longest consecutive run of needle characters found in haystack.

    Uses a sliding window approach: for each substring length from longest
    to shortest, check if it appears in the haystack.
    """
    needle_len = len(needle)
    # Check decreasing lengths from the full string down to 3 chars
    for length in range(min(needle_len, 20), 2, -1):
        for start in range(needle_len - length + 1):
            sub = needle[start : start + length]
            if sub in haystack:
                return length
    return 0


def filter_efficiencies(efficiencies: list[int], threshold: int = 50) -> list[int]:
    """Filter out low-efficiency reflections."""
    return [e for e in efficiencies if e >= threshold]


def score_payload_executability(
    response_text: str,
    payload: str,
    context_type: str,
) -> tuple[int, str]:
    """Score how executable a payload is in a given response context.

    Combines reflection efficiency with context-awareness to determine
    how likely the payload is to execute.

    Args:
        response_text: Response body after injecting the payload.
        payload: The payload that was injected.
        context_type: The HTML context where the payload landed.

    Returns:
        Tuple of (score 0-100, verdict string).
    """
    efficiency = reflection_efficiency(response_text, payload)

    # Context-based bonus/penalty
    context_modifier = {
        "html": 0,
        "attribute": -10,
        "script": 20,
        "comment": -30,
        "dead": -50,
    }.get(context_type, -20)

    score = max(0, min(100, efficiency + context_modifier))

    if score >= 90:
        verdict = "highly_executable"
    elif score >= 70:
        verdict = "likely_executable"
    elif score >= 50:
        verdict = "possibly_executable"
    elif score >= 30:
        verdict = "filtered"
    else:
        verdict = "blocked"

    return score, verdict
