"""Text processing utilities for passive analysis.

Contains functions for text normalization, field extraction, value redaction,
entropy calculation, and randomness detection.
Extracted from passive_analysis_runtime.py for better separation of concerns.
"""

import math
import re
from typing import Any

# Pre-compiled regex for text normalization and field extraction
_NORMALIZE_DIGITS_RE = re.compile(r"\d+")
_EXTRACT_KEY_FIELDS_RE = re.compile(r'"([A-Za-z_][A-Za-z0-9_-]{2,})"\s*:')


def redacted_snippet(body: str, start: int, end: int, context: int = 48) -> str:
    """Extract a snippet around a match with redacted sensitive value."""
    snippet_start = max(0, start - context)
    snippet_end = min(len(body), end + context)
    before = body[snippet_start:start]
    matched = body[start:end]
    after = body[end:snippet_end]
    cleaned = f"{before}{redact_value(matched)}{after}".replace("\r", " ").replace("\n", " ")
    return cleaned[:180]


def redact_value(value: str) -> str:
    """Redact a sensitive value, showing only first/last 4 chars for long values."""
    if len(value) <= 8:
        return "[redacted]"
    return f"{value[:4]}...[redacted]...{value[-4:]}"


def normalize_compare_text(value: str) -> str:
    """Normalize text for comparison by replacing digits with zeros."""
    return _NORMALIZE_DIGITS_RE.sub("0", value or "")[:4000]


def extract_key_fields(value: str) -> set[str]:
    """Extract JSON field names from a response body."""
    return {match.group(1).lower() for match in _EXTRACT_KEY_FIELDS_RE.finditer(value or "")}


def json_headers(headers: dict[str, Any]) -> str:
    """Format headers as a space-separated string for analysis."""
    return " ".join(f"{key}:{value}" for key, value in (headers or {}).items())


def shannon_entropy(value: str) -> float:
    """Calculate Shannon entropy of a string to measure randomness."""
    if not value:
        return 0.0
    length = len(value)
    frequency: dict[str, int] = {}
    for char in value:
        frequency[char] = frequency.get(char, 0) + 1
    return -sum((count / length) * math.log2(count / length) for count in frequency.values())


def looks_random(value: str) -> bool:
    """Determine if a string appears random using multiple heuristics."""
    if not value or len(value) < 6:
        return False
    entropy = shannon_entropy(value)
    if entropy < 3.0:
        return False
    alpha_count = sum(1 for c in value if c.isalpha())
    digit_count = sum(1 for c in value if c.isdigit())
    if alpha_count == 0 or digit_count == 0:
        return entropy > 4.0
    ratio = min(alpha_count, digit_count) / max(alpha_count, digit_count)
    return ratio > 0.15 and entropy > 3.5
