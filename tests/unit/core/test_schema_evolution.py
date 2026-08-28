import unittest

from src.core.contracts.command_envelope import (
    SchemaMigrationRegistry,
)


class TestSchemaEvolutionBidirectional(unittest.TestCase):
    def setUp(self) -> None:
        self.registry = SchemaMigrationRegistry()

        # v1 -> v2: rename "units" to "units_allocated"
        def upcast_v1_v2(payload: dict) -> dict:
            p = dict(payload)
            if "units" in p:
                p["units_allocated"] = p.pop("units")
            return p

        # v2 -> v3: add default priority = "NORMAL"
        def upcast_v2_v3(payload: dict) -> dict:
            p = dict(payload)
            p.setdefault("priority", "NORMAL")
            return p

        # v3 -> v2: drop priority
        def downcast_v3_v2(payload: dict) -> dict:
            p = dict(payload)
            p.pop("priority", None)
            return p

        # v2 -> v1: rename "units_allocated" back to "units"
        def downcast_v2_v1(payload: dict) -> dict:
            p = dict(payload)
            if "units_allocated" in p:
                p["units"] = p.pop("units_allocated")
            return p

        self.registry.register_upcaster("AllocateSubLease", 1, 2, upcast_v1_v2)
        self.registry.register_upcaster("AllocateSubLease", 2, 3, upcast_v2_v3)
        self.registry.register_downcaster("AllocateSubLease", 3, 2, downcast_v3_v2)
        self.registry.register_downcaster("AllocateSubLease", 2, 1, downcast_v2_v1)

    def test_forward_compatibility_upcasting(self) -> None:
        raw_v1 = {
            "command_type": "AllocateSubLease",
            "schema_version": 1,
            "payload": {"sublease_id": "sl_1", "units": 500},
        }
        upcasted = self.registry.upcast(raw_v1, target_version=3)
        self.assertEqual(upcasted["schema_version"], 3)
        self.assertEqual(upcasted["payload"]["units_allocated"], 500)
        self.assertEqual(upcasted["payload"]["priority"], "NORMAL")
        self.assertNotIn("units", upcasted["payload"])

    def test_reverse_compatibility_downcasting(self) -> None:
        raw_v3 = {
            "command_type": "AllocateSubLease",
            "schema_version": 3,
            "payload": {"sublease_id": "sl_3", "units_allocated": 750, "priority": "HIGH"},
        }
        downcasted = self.registry.downcast(raw_v3, target_version=1)
        self.assertEqual(downcasted["schema_version"], 1)
        self.assertEqual(downcasted["payload"]["units"], 750)
        self.assertNotIn("priority", downcasted["payload"])

    def test_unknown_field_preservation_passthrough(self) -> None:
        """Newer v4 command reaches a v2 node without explicit downcaster."""
        raw_v4 = {
            "command_type": "UnknownFutureCommand",
            "schema_version": 4,
            "payload": {"future_field": "quantum_token_123", "target_host": "alpha.corp"},
        }
        downcasted = self.registry.downcast(raw_v4, target_version=2)
        self.assertEqual(downcasted["schema_version"], 2)
        self.assertIn("_unknown_fields", downcasted)
        self.assertEqual(downcasted["_unknown_fields"]["v4"]["future_field"], "quantum_token_123")


if __name__ == "__main__":
    unittest.main()
