


class TestTelemetryStoreConfidenceModels:
    """Tests for confidence model operations."""

    def test_save_and_get_confidence_model(self, store):
        model = {
            "model_id": "cm-001",
            "category": "idor",
            "plugin_name": "idor_candidate_finder",
            "platt_A": -1.5,
            "platt_B": 0.3,
            "sample_size": 100,
            "accuracy": 0.85,
            "updated_at": "2026-04-01T10:30:00",
        }
        store.save_confidence_model(model)
        result = store.get_confidence_model("idor", "idor_candidate_finder")
        assert result is not None
        assert result["platt_A"] == -1.5
        assert result["sample_size"] == 100

    def test_get_confidence_model_nonexistent(self, store):
        result = store.get_confidence_model("nonexistent", "plugin")
        assert result is None
