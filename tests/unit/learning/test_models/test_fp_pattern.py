import json

from src.learning.models.fp_pattern import FPPattern


class TestFPPattern:
    """Tests for FPPattern model."""

    def test_create(self):
        pattern = FPPattern.create(
            category="waf_block",
            status_codes={403, 406},
            body_indicators=["blocked", "cloudflare"],
        )
        assert pattern.pattern_id.startswith("fp-")
        assert pattern.category == "waf_block"
        assert 403 in pattern.status_codes
        assert pattern.fp_probability == 0.5

    def test_create_defaults(self):
        pattern = FPPattern.create(category="generic")
        assert pattern.status_codes == set()
        assert pattern.body_indicators == []
        assert pattern.header_indicators == {}
        assert pattern.fp_probability == 0.5
        assert pattern.is_active is True

    def test_update_with_fp(self):
        pattern = FPPattern.create(category="waf_block")
        pattern.update(is_fp=True, is_tp=False)
        assert pattern.occurrence_count == 1
        assert pattern.confirmed_fp_count == 1
        assert pattern.fp_probability > 0.5

    def test_update_with_tp(self):
        pattern = FPPattern.create(category="waf_block")
        pattern.update(is_fp=False, is_tp=True)
        assert pattern.fp_probability < 0.5

    def test_update_both(self):
        pattern = FPPattern.create(category="mixed")
        pattern.update(is_fp=True, is_tp=True)
        assert pattern.occurrence_count == 1
        assert pattern.confirmed_fp_count == 1
        assert pattern.confirmed_tp_count == 1

    def test_update_neither(self):
        pattern = FPPattern.create(category="neutral")
        pattern.update(is_fp=False, is_tp=False)
        assert pattern.occurrence_count == 1
        assert pattern.confirmed_fp_count == 0
        assert pattern.confirmed_tp_count == 0

    def test_suppression_action_escalation(self):
        pattern = FPPattern.create(category="noisy")
        for _ in range(20):
            pattern.update(is_fp=True, is_tp=False)
        assert pattern.suppression_action == "suppress"
        assert pattern.fp_probability > 0.9

    def test_suppression_action_downgrade(self):
        pattern = FPPattern.create(category="moderate")
        for _ in range(7):
            pattern.update(is_fp=True, is_tp=False)
        assert pattern.suppression_action == "downgrade"

    def test_suppression_action_flag(self):
        pattern = FPPattern.create(category="low_noise")
        pattern.update(is_fp=False, is_tp=True)
        assert pattern.suppression_action == "flag"

    def test_deactivate_when_confident_not_fp(self):
        pattern = FPPattern.create(category="legitimate")
        for _ in range(30):
            pattern.update(is_fp=False, is_tp=True)
        assert pattern.is_active is False

    def test_confidence_increases_with_samples(self):
        pattern = FPPattern.create(category="test")
        pattern.update(is_fp=True, is_tp=False)
        conf1 = pattern.confidence
        for _ in range(20):
            pattern.update(is_fp=True, is_tp=False)
        assert pattern.confidence >= conf1

    def test_to_db_row_and_from_db_row(self):
        pattern = FPPattern.create(
            category="waf_block",
            status_codes={403},
            body_indicators=["blocked"],
        )
        pattern.update(is_fp=True, is_tp=False)
        row = pattern.to_db_row()
        restored = FPPattern.from_db_row(row)
        assert restored.category == pattern.category
        assert restored.fp_probability == pattern.fp_probability
        assert restored.occurrence_count == pattern.occurrence_count

    def test_to_db_row_serializes_sets(self):
        pattern = FPPattern.create(
            category="test",
            status_codes={403, 500},
            body_indicators=["error"],
            header_indicators={"X-Blocked": "true"},
        )
        row = pattern.to_db_row()
        assert isinstance(row["status_code_pattern"], str)
        assert isinstance(row["body_pattern"], str)
        assert isinstance(row["header_pattern"], str)
        parsed = json.loads(row["status_code_pattern"])
        assert 403 in parsed
        assert 500 in parsed

    def test_from_db_row_empty_fields(self):
        row = {
            "pattern_id": "fp-empty",
            "category": "test",
            "status_code_pattern": None,
            "body_pattern": None,
            "header_pattern": None,
            "response_similarity": 0.9,
            "fp_probability": 0.5,
            "confidence": 0.0,
            "occurrence_count": 0,
            "confirmed_fp_count": 0,
            "confirmed_tp_count": 0,
            "is_active": 1,
            "suppression_action": "flag",
            "first_seen": None,
            "last_seen": None,
            "created_at": "2026-04-01T10:00:00",
            "updated_at": "2026-04-01T10:00:00",
        }
        pattern = FPPattern.from_db_row(row)
        assert pattern.status_codes == set()
        assert pattern.body_indicators == []
        assert pattern.header_indicators == {}

    def test_round_trip_preserves_data(self):
        pattern = FPPattern.create(
            category="round_trip",
            status_codes={404, 500},
            body_indicators=["not found", "error"],
            header_indicators={"X-Error": "true"},
        )
        pattern.response_similarity_threshold = 0.85
        pattern.update(is_fp=True, is_tp=False)
        pattern.update(is_fp=True, is_tp=False)
        row = pattern.to_db_row()
        restored = FPPattern.from_db_row(row)
        assert restored.category == pattern.category
        assert restored.status_codes == pattern.status_codes
        assert restored.body_indicators == pattern.body_indicators
        assert restored.header_indicators == pattern.header_indicators
        assert restored.fp_probability == pattern.fp_probability
        assert restored.confidence == pattern.confidence
        assert restored.occurrence_count == pattern.occurrence_count
        assert restored.confirmed_fp_count == pattern.confirmed_fp_count
        assert restored.confirmed_tp_count == pattern.confirmed_tp_count
        assert restored.is_active == pattern.is_active
        assert restored.suppression_action == pattern.suppression_action
