"""False-positive pattern tracking and learning.

Replaces static FP_SUPPRESSION_PATTERNS with learned patterns that
adapt based on observed outcomes. Uses Bayesian updating to track
FP probability and confidence for each pattern.
"""

import logging
from typing import Any

from src.learning.models.fp_pattern import FPPattern
from src.learning.telemetry_store import TelemetryStore

logger = logging.getLogger(__name__)

# Default static patterns (fallback when no learned patterns exist)
_DEFAULT_FP_PATTERNS: dict[str, dict[str, Any]] = {
    "rate_limit": {
        "status_codes": {429, 503},
        "body_indicators": [
            "rate limit",
            "too many requests",
            "throttl",
            "slow down",
            "try again later",
        ],
    },
    "waf_block": {
        "status_codes": {403, 406, 418},
        "body_indicators": [
            "blocked",
            "waf",
            "cloudflare",
            "akamai",
            "incapsula",
            "forbidden",
            "access denied",
        ],
    },
    "cdn_error": {
        "status_codes": {502, 503, 504, 520, 521, 522, 523, 524, 525, 526, 527},
        "body_indicators": [
            "bad gateway",
            "service unavailable",
            "origin error",
            "connection timed out",
        ],
    },
    "generic_error": {
        "status_codes": {500, 501, 505},
        "body_indicators": [
            "internal server error",
            "not implemented",
            "http version not supported",
        ],
    },
}


class FPTracker:
    """Tracks and learns false-positive patterns from scan outcomes."""

    def __init__(self, store: TelemetryStore):
        self.store = store
        self._cache: dict[str, FPPattern] = {}
        self._loaded = False

    def _ensure_loaded(self) -> None:
        """Load FP patterns from the store into cache."""
        if self._loaded:
            return
        rows = self.store.get_fp_patterns()
        for row in rows:
            pattern = FPPattern.from_db_row(row)
            self._cache[pattern.pattern_id] = pattern

        # If no patterns exist, seed with defaults
        if not self._cache:
            for category, config in _DEFAULT_FP_PATTERNS.items():
                pattern = FPPattern.create(
                    category=category,
                    status_codes=config["status_codes"],
                    body_indicators=config["body_indicators"],
                )
                self._cache[pattern.pattern_id] = pattern
                self.store.upsert_fp_pattern(pattern.to_db_row())

        self._loaded = True

    async def update_from_run(self, run_id: str) -> int:
        """Update FP patterns based on findings from a completed run.

        Returns the number of patterns updated.
        """
        self._ensure_loaded()
        findings = self.store.get_findings_for_run(run_id)
        if not findings:
            return 0

        updated_count = 0

        for finding in findings:
            response_status = finding.get("response_status")
            body = finding.get("evidence", "")
            category = finding.get("category", "general")

            is_fp = finding.get("decision") == "DROP"
            is_tp = finding.get("lifecycle_state") in ("VALIDATED", "EXPLOITABLE")

            # Match against existing patterns
            matched = self._match_pattern(response_status or 0, body, {}, category)

            if matched:
                matched.update(is_fp=is_fp, is_tp=is_tp)
                self._cache[matched.pattern_id] = matched
                self.store.upsert_fp_pattern(matched.to_db_row())
                updated_count += 1
            elif is_fp:
                # Create new pattern candidate
                pattern = FPPattern.create(
                    category=category,
                    status_codes={response_status} if response_status else set(),
                    body_indicators=[body[:100]] if body else [],
                )
                pattern.update(is_fp=True, is_tp=is_tp)
                self._cache[pattern.pattern_id] = pattern
                self.store.upsert_fp_pattern(pattern.to_db_row())
                updated_count += 1

        if updated_count > 0:
            logger.info(
                "FP tracker updated %d patterns from run %s",
                updated_count,
                run_id,
            )

        return updated_count

    def _match_pattern(
        self,
        status_code: int,
        body: str,
        headers: dict,
        category: str,
    ) -> FPPattern | None:
        """Match response characteristics against known FP patterns."""
        body_lower = body.lower()

        for pattern in self._cache.values():
            if not pattern.is_active:
                continue

            # Check status code match
            if status_code not in pattern.status_codes:
                continue

            # Check body indicators
            body_match = any(indicator in body_lower for indicator in pattern.body_indicators)

            if body_match:
                return pattern

        return None

    def classify_response(
        self,
        status_code: int,
        body: str,
        headers: dict | None = None,
        category: str = "general",
    ) -> tuple[bool, str, float]:
        """Classify a response as likely FP or not.

        Returns: (is_likely_fp, pattern_category, confidence)
        """
        self._ensure_loaded()
        headers = headers or {}

        pattern = self._match_pattern(status_code, body, headers, category)

        if pattern and pattern.is_active:
            return (
                pattern.fp_probability > 0.7,
                pattern.category,
                pattern.confidence,
            )

        # Fall back to default static patterns
        return self._classify_static(status_code, body)

    def _classify_static(self, status_code: int, body: str) -> tuple[bool, str, float]:
        """Classify using static patterns (fallback)."""
        body_lower = body.lower()

        for cat, config in _DEFAULT_FP_PATTERNS.items():
            if status_code in config["status_codes"]:
                if any(ind in body_lower for ind in config["body_indicators"]):
                    return (True, cat, 0.5)

        return (False, "", 0.0)

    def get_active_pattern_count(self) -> int:
        """Get the number of active FP patterns."""
        self._ensure_loaded()
        return sum(1 for p in self._cache.values() if p.is_active)

    def get_fp_rate_for_category(self, category: str) -> float:
        """Get the historical FP rate for a category."""
        return self.store.get_fp_rate_for_pattern(category, "any")
