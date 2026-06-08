


class TestTelemetryStoreFPPatterns:
    """Tests for FP pattern operations."""

    def test_upsert_and_get_fp_patterns(self, store):
        pattern = {
            "pattern_id": "fp-test-001",
            "category": "waf_block",
            "status_code_pattern": "[403, 406]",
            "body_pattern": '["blocked"]',
            "header_pattern": "{}",
            "response_similarity": 0.9,
            "first_seen": "2026-04-01T10:00:00",
            "last_seen": "2026-04-01T10:00:00",
            "occurrence_count": 5,
            "confirmed_fp_count": 4,
            "confirmed_tp_count": 1,
            "fp_probability": 0.8,
            "confidence": 0.7,
            "is_active": 1,
            "suppression_action": "downgrade",
            "created_at": "2026-04-01T10:00:00",
            "updated_at": "2026-04-01T10:00:00",
        }
        store.upsert_fp_pattern(pattern)
        patterns = store.get_fp_patterns()
        assert len(patterns) == 1
        assert patterns[0]["category"] == "waf_block"

    def test_get_active_fp_pattern_count(self, store):
        pattern = {
            "pattern_id": "fp-test-002",
            "category": "rate_limit",
            "status_code_pattern": "[429]",
            "body_pattern": '["rate limit"]',
            "header_pattern": "{}",
            "response_similarity": 0.9,
            "first_seen": "2026-04-01T10:00:00",
            "last_seen": "2026-04-01T10:00:00",
            "occurrence_count": 3,
            "confirmed_fp_count": 3,
            "confirmed_tp_count": 0,
            "fp_probability": 0.9,
            "confidence": 0.8,
            "is_active": 1,
            "suppression_action": "suppress",
            "created_at": "2026-04-01T10:00:00",
            "updated_at": "2026-04-01T10:00:00",
        }
        store.upsert_fp_pattern(pattern)
        count = store.get_active_fp_pattern_count()
        assert count == 1

    def test_get_fp_patterns_by_category(self, store):
        pattern1 = {
            "pattern_id": "fp-cat-001",
            "category": "waf_block",
            "status_code_pattern": "[403]",
            "body_pattern": "[]",
            "header_pattern": "{}",
            "response_similarity": 0.9,
            "first_seen": "2026-04-01T10:00:00",
            "last_seen": "2026-04-01T10:00:00",
            "occurrence_count": 1,
            "confirmed_fp_count": 1,
            "confirmed_tp_count": 0,
            "fp_probability": 0.7,
            "confidence": 0.5,
            "is_active": 1,
            "suppression_action": "downgrade",
            "created_at": "2026-04-01T10:00:00",
            "updated_at": "2026-04-01T10:00:00",
        }
        pattern2 = {
            "pattern_id": "fp-cat-002",
            "category": "rate_limit",
            "status_code_pattern": "[429]",
            "body_pattern": "[]",
            "header_pattern": "{}",
            "response_similarity": 0.9,
            "first_seen": "2026-04-01T10:00:00",
            "last_seen": "2026-04-01T10:00:00",
            "occurrence_count": 1,
            "confirmed_fp_count": 1,
            "confirmed_tp_count": 0,
            "fp_probability": 0.7,
            "confidence": 0.5,
            "is_active": 1,
            "suppression_action": "downgrade",
            "created_at": "2026-04-01T10:00:00",
            "updated_at": "2026-04-01T10:00:00",
        }
        store.upsert_fp_pattern(pattern1)
        store.upsert_fp_pattern(pattern2)
        patterns = store.get_fp_patterns(category="waf_block")
        assert len(patterns) == 1
        assert patterns[0]["category"] == "waf_block"

    def test_get_fp_patterns_inactive_excluded(self, store):
        pattern = {
            "pattern_id": "fp-inactive-001",
            "category": "noise",
            "status_code_pattern": "[500]",
            "body_pattern": "[]",
            "header_pattern": "{}",
            "response_similarity": 0.9,
            "first_seen": "2026-04-01T10:00:00",
            "last_seen": "2026-04-01T10:00:00",
            "occurrence_count": 1,
            "confirmed_fp_count": 0,
            "confirmed_tp_count": 1,
            "fp_probability": 0.3,
            "confidence": 0.5,
            "is_active": 0,
            "suppression_action": "flag",
            "created_at": "2026-04-01T10:00:00",
            "updated_at": "2026-04-01T10:00:00",
        }
        store.upsert_fp_pattern(pattern)
        patterns = store.get_fp_patterns(active_only=True)
        assert len(patterns) == 0

    def test_upsert_fp_pattern_with_bool_is_active(self, store):
        pattern = {
            "pattern_id": "fp-bool-001",
            "category": "test",
            "status_code_pattern": "[404]",
            "body_pattern": "[]",
            "header_pattern": "{}",
            "response_similarity": 0.9,
            "first_seen": "2026-04-01T10:00:00",
            "last_seen": "2026-04-01T10:00:00",
            "occurrence_count": 1,
            "confirmed_fp_count": 1,
            "confirmed_tp_count": 0,
            "fp_probability": 0.7,
            "confidence": 0.5,
            "is_active": True,
            "suppression_action": "downgrade",
            "created_at": "2026-04-01T10:00:00",
            "updated_at": "2026-04-01T10:00:00",
        }
        store.upsert_fp_pattern(pattern)
        patterns = store.get_fp_patterns()
        assert len(patterns) == 1
        assert patterns[0]["is_active"] == 1
