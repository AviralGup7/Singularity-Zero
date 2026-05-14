"""Pattern matching with optional Hyperscan acceleration."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class PatternMatch:
    pattern_id: str
    start: int
    end: int


class RegexPatternMatcher:
    """Portable regex matcher used when Hyperscan is unavailable."""

    def __init__(self, patterns: dict[str, str], flags: int = re.IGNORECASE) -> None:
        self._compiled = {
            pattern_id: re.compile(pattern, flags) for pattern_id, pattern in patterns.items()
        }

    def scan(self, text: str | bytes) -> list[PatternMatch]:
        haystack = text.decode("utf-8", errors="ignore") if isinstance(text, bytes) else text
        matches: list[PatternMatch] = []
        for pattern_id, compiled in self._compiled.items():
            matches.extend(
                PatternMatch(pattern_id=pattern_id, start=match.start(), end=match.end())
                for match in compiled.finditer(haystack)
            )
        return matches


class HyperscanPatternMatcher:
    """Hyperscan-backed matcher for high-throughput literal/regex scans."""

    def __init__(self, patterns: dict[str, str]) -> None:
        import hyperscan  # type: ignore[import-not-found]

        self._hyperscan = hyperscan
        self._ids = {idx: pattern_id for idx, pattern_id in enumerate(patterns, start=1)}
        self._db = hyperscan.Database()
        expressions = [pattern.encode("utf-8") for pattern in patterns.values()]
        ids = list(self._ids)
        flags = [hyperscan.HS_FLAG_CASELESS | hyperscan.HS_FLAG_UTF8] * len(expressions)
        self._db.compile(expressions=expressions, ids=ids, elements=len(expressions), flags=flags)

    def scan(self, text: str | bytes) -> list[PatternMatch]:
        data = text if isinstance(text, bytes) else text.encode("utf-8")
        matches: list[PatternMatch] = []

        def on_match(pattern_id: int, from_: int, to: int, flags: int, context: Any) -> None:
            _ = (flags, context)
            matches.append(PatternMatch(self._ids[pattern_id], from_, to))

        self._db.scan(data, match_event_handler=on_match)
        return matches


def create_pattern_matcher(
    patterns: dict[str, str],
    *,
    prefer_acceleration: bool = True,
) -> RegexPatternMatcher | HyperscanPatternMatcher:
    """Create the fastest available pattern matcher for the current host."""
    if prefer_acceleration:
        try:
            return HyperscanPatternMatcher(patterns)
        except Exception as exc:
            logger.debug("Hyperscan matcher unavailable; falling back to regex: %s", exc)
    return RegexPatternMatcher(patterns)
