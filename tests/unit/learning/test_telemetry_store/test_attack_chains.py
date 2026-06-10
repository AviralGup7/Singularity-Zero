class TestTelemetryStoreAttackChains:
    """Tests for attack chain operations."""

    def test_record_and_get_attack_chains(self, store):
        chain = {
            "chain_id": "chain-001",
            "pattern_name": "auth_bypass_chain",
            "description": "IDOR leads to auth bypass",
            "finding_ids": '["f1", "f2"]',
            "confidence": 0.85,
            "risk_score": 8.5,
            "validation_status": "pending",
            "validation_result": None,
            "detected_at": "2026-04-01T10:20:00",
        }
        store.record_attack_chain(chain)
        chains = store.get_attack_chains()
        assert len(chains) == 1
        assert chains[0]["pattern_name"] == "auth_bypass_chain"

    def test_get_attack_chains_by_pattern(self, store):
        store.record_attack_chain(
            {
                "chain_id": "chain-pattern-001",
                "pattern_name": "xss_chain",
                "description": "XSS chain",
                "finding_ids": '["f3"]',
                "confidence": 0.7,
                "risk_score": 6.0,
                "validation_status": "confirmed",
                "validation_result": "verified",
                "detected_at": "2026-04-01T10:20:00",
            }
        )
        chains = store.get_attack_chains(pattern_name="xss_chain")
        assert len(chains) == 1

    def test_get_attack_chains_by_status(self, store):
        store.record_attack_chain(
            {
                "chain_id": "chain-status-001",
                "pattern_name": "test_chain",
                "description": "Test",
                "finding_ids": '["f4"]',
                "confidence": 0.6,
                "risk_score": 5.0,
                "validation_status": "pending",
                "validation_result": None,
                "detected_at": "2026-04-01T10:20:00",
            }
        )
        chains = store.get_attack_chains(status="pending")
        assert len(chains) == 1

    def test_get_attack_chains_limit(self, store):
        for i in range(10):
            store.record_attack_chain(
                {
                    "chain_id": f"chain-limit-{i:03d}",
                    "pattern_name": "test",
                    "description": "Test",
                    "finding_ids": f'["f{i}"]',
                    "confidence": 0.5,
                    "risk_score": float(i),
                    "validation_status": "pending",
                    "validation_result": None,
                    "detected_at": "2026-04-01T10:20:00",
                }
            )
        chains = store.get_attack_chains(limit=3)
        assert len(chains) == 3
