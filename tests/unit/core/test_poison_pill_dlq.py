import unittest
from types import SimpleNamespace
from src.core.frontier.event_delivery import (
    DeliveryLedger,
    dispatch_committed_findings,
)


class TestPoisonPillEventBusProtection(unittest.TestCase):
    def test_poison_pill_quarantine_after_max_attempts(self) -> None:
        ledger = DeliveryLedger(max_delivery_attempts=3)
        settle_res = SimpleNamespace(
            execution_id="exec_1",
            wal_id="wal_001",
            command_id="cmd_001",
            attempt_id="att_001",
            settlement_id="set_001",
            status="COMMITTED",
        )

        def failing_emit(*args, **kwargs) -> None:
            raise ValueError("Consumer deserialization explosion!")

        # Dispatch attempt 1 -> fails, attempt count 1
        dispatch_committed_findings(
            settle_res=settle_res,
            stage_name="sqli_scan",
            findings=[{"title": "Malformed SQLi"}],
            emit=failing_emit,
            event_type="FINDING_CREATED",
            delivery_ledger=ledger,
        )
        self.assertEqual(len(ledger.get_poison_events()), 0)

        # Dispatch attempt 2 -> fails, attempt count 2
        dispatch_committed_findings(
            settle_res=settle_res,
            stage_name="sqli_scan",
            findings=[{"title": "Malformed SQLi"}],
            emit=failing_emit,
            event_type="FINDING_CREATED",
            delivery_ledger=ledger,
        )
        self.assertEqual(len(ledger.get_poison_events()), 0)

        # Dispatch attempt 3 -> fails, reaches max attempts -> quarantined to DLQ!
        dispatch_committed_findings(
            settle_res=settle_res,
            stage_name="sqli_scan",
            findings=[{"title": "Malformed SQLi"}],
            emit=failing_emit,
            event_type="FINDING_CREATED",
            delivery_ledger=ledger,
        )
        poison = ledger.get_poison_events()
        self.assertEqual(len(poison), 1)
        # Quarantined event is marked as already delivered / quarantined to prevent cascade hangs
        del_id = list(poison.keys())[0]
        self.assertTrue(ledger.already_delivered(del_id))
        self.assertTrue(ledger.is_poisoned(del_id))


if __name__ == "__main__":
    unittest.main()
