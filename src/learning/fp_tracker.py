"""False-positive pattern tracking and learning.

Replaces static FP_SUPPRESSION_PATTERNS with learned patterns that
adapt based on observed outcomes. Uses Bayesian updating to track
FP probability and confidence for each pattern.
"""

from __future__ import annotations

import logging
from typing import Any

from src.learning.models.fp_pattern import FPPattern
from src.learning.repositories.redis_fp_repo import RedisFPRepository
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

    def __init__(
        self,
        store: TelemetryStore,
        mesh_sync: Any | None = None,
        redis_repo: RedisFPRepository | None = None,
    ):
        self.store = store
        self._cache: dict[str, FPPattern] = {}
        self._loaded = False
        self._mesh_sync = mesh_sync
        self._redis_repo = redis_repo

        if self._mesh_sync:
            # Note: The caller is responsible for calling start_listening
            # which will invoke this callback.
            self._mesh_sync_task = None

    async def _on_mesh_update(self, data: dict[str, Any]) -> None:
        """Handle incoming FP pattern updates from other nodes."""
        try:
            pattern = FPPattern.from_db_row(data)
            logger.debug("FP tracker received mesh update for pattern %s", pattern.pattern_id)

            await self._ensure_loaded_async()
            existing = self._cache.get(pattern.pattern_id)

            # Merge logic: use the one with higher occurrence count or more recent update
            if not existing or pattern.occurrence_count > existing.occurrence_count:
                self._cache[pattern.pattern_id] = pattern
                self.store.upsert_fp_pattern(pattern.to_db_row())
                if self._redis_repo:
                    await self._redis_repo.upsert_pattern(pattern)
                logger.info("FP tracker synced mesh pattern %s", pattern.pattern_id)
        except Exception as e:
            logger.warning("FP tracker failed to process mesh update: %s", e, exc_info=True)

    def _ensure_loaded(self) -> None:
        """Load FP patterns from the store into cache (synchronous)."""
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

    async def _ensure_loaded_async(self) -> None:
        """Load FP patterns from Redis and store into cache (asynchronous)."""
        if self._loaded:
            return

        # Try Redis first if available
        if self._redis_repo:
            patterns = await self._redis_repo.list_patterns(active_only=False)
            if patterns:
                for pattern in patterns:
                    self._cache[pattern.pattern_id] = pattern
                    # Sync to local store
                    self.store.upsert_fp_pattern(pattern.to_db_row())
                self._loaded = True
                return

        self._ensure_loaded()

    async def update_from_run(self, run_id: str) -> int:
        """Update FP patterns based on findings from a completed run.

        Returns the number of patterns updated.
        """
        await self._ensure_loaded_async()
        findings = self.store.get_findings_for_run(run_id)
        if not findings:
            return 0

        updated_count = 0
        patterns_created = 0
        patterns_updated = 0
        patterns_to_upsert = []

        for finding in findings:
            response_status = finding.get("response_status")
            body = finding.get("evidence", "")
            category = finding.get("category", "general")

            is_fp = finding.get("decision") == "DROP"
            is_tp = finding.get("lifecycle_state") in ("VALIDATED", "EXPLOITABLE")

            headers = finding.get("headers", {})
            if isinstance(headers, str):
                import json

                try:
                    headers = json.loads(headers)
                except Exception:
                    headers = {}

            # Match against existing patterns
            matched = self._match_pattern(response_status or 0, body, headers, category)

            if matched:
                matched.update(is_fp=is_fp, is_tp=is_tp)
                self._cache[matched.pattern_id] = matched
                patterns_to_upsert.append(matched)
                patterns_updated += 1
                updated_count += 1
                if self._mesh_sync:
                    await self._mesh_sync.publish(matched.to_db_row())
            elif is_fp:
                # Create new pattern candidate
                pattern = FPPattern.create(
                    category=category,
                    status_codes={response_status} if response_status else set(),
                    body_indicators=[body[:100]] if body else [],
                )
                pattern.update(is_fp=True, is_tp=is_tp)
                self._cache[pattern.pattern_id] = pattern
                patterns_to_upsert.append(pattern)
                patterns_created += 1
                updated_count += 1
                if self._mesh_sync:
                    await self._mesh_sync.publish(pattern.to_db_row())

        if patterns_to_upsert:
            try:
                self.store.upsert_fp_patterns([p.to_db_row() for p in patterns_to_upsert])
                if self._redis_repo:
                    for p in patterns_to_upsert:
                        await self._redis_repo.upsert_pattern(p)
            except Exception as e:
                logger.error("FP tracker failed to batch upsert patterns: %s", e, exc_info=True)

        if updated_count > 0:
            logger.info(
                "FP tracker updated %d patterns (%d created, %d updated) from run %s",
                updated_count,
                patterns_created,
                patterns_updated,
                run_id,
            )

        try:
            from src.infrastructure.observability.metrics import get_metrics

            m = get_metrics()
            m.counter("fp_tracker_patterns_created_total").inc(patterns_created)
            m.counter("fp_tracker_patterns_updated_total").inc(patterns_updated)
        except Exception:
            pass

        return updated_count

    async def add_manual_fp(
        self,
        category: str,
        status_code: int | None = None,
        body_indicator: str | None = None,
    ) -> FPPattern:
        """Manually add or update a false positive pattern from triage and sync it mesh-wide."""
        await self._ensure_loaded_async()

        # Try to find if there's an existing pattern for this category and characteristics
        matched = None
        for pattern in self._cache.values():
            if pattern.category == category:
                if status_code and status_code in pattern.status_codes:
                    matched = pattern
                    break
                if body_indicator and any(
                    indicator in body_indicator.lower() for indicator in pattern.body_indicators
                ):
                    matched = pattern
                    break

        if matched:
            matched.update(is_fp=True, is_tp=False)
            self._cache[matched.pattern_id] = matched
            self.store.upsert_fp_pattern(matched.to_db_row())
            if self._redis_repo:
                await self._redis_repo.upsert_pattern(matched)
            if self._mesh_sync:
                await self._mesh_sync.publish(matched.to_db_row())
            return matched
        else:
            pattern = FPPattern.create(
                category=category,
                status_codes={status_code} if status_code else set(),
                body_indicators=[body_indicator[:100]] if body_indicator else [],
            )
            pattern.update(is_fp=True, is_tp=False)
            self._cache[pattern.pattern_id] = pattern
            self.store.upsert_fp_pattern(pattern.to_db_row())
            if self._redis_repo:
                await self._redis_repo.upsert_pattern(pattern)
            if self._mesh_sync:
                await self._mesh_sync.publish(pattern.to_db_row())
            return pattern

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

            # Check body indicators if defined
            if pattern.body_indicators:
                body_match = any(indicator in body_lower for indicator in pattern.body_indicators)
            else:
                body_match = True

            # Check header indicators if defined
            if pattern.header_indicators:
                header_match = True
                for hk, hv in pattern.header_indicators.items():
                    hk_lower = hk.lower()
                    matched_val = False
                    for real_k, real_v in headers.items():
                        if real_k.lower() == hk_lower:
                            if str(hv).lower() in str(real_v).lower():
                                matched_val = True
                                break
                    if not matched_val:
                        header_match = False
                        break
            else:
                header_match = True

            if body_match and header_match:
                return pattern

        return None
