import unittest
from src.core.frontier.state import HybridLogicalClock, compute_clock_health
from src.core.frontier.state_authority import StateAuthority
from src.decision.authorization import BlastRadiusConstraint, AuthorizedExecutionTicket
from src.decision.models import ExecutionRequest, TargetSpec
from src.core.events.event_bus import EventBus, EventType, PipelineEvent
from src.core.tenant_context import TenantContext


class TestAuditFixes(unittest.TestCase):
    def test_clock_health_drift_monitor(self) -> None:
        hlc = HybridLogicalClock()
        health = compute_clock_health(hlc, max_skew_threshold_sec=5.0)
        self.assertTrue(health.is_skew_healthy)
        self.assertLessEqual(health.hlc_vs_monotonic_skew_sec, 5.0)

        data = health.to_dict()
        self.assertIn("hlc_physical_time", data)
        self.assertIn("is_skew_healthy", data)

    def test_state_authority_snapshot_age_metric(self) -> None:
        authority = StateAuthority()
        self.assertGreaterEqual(authority.time_since_last_snapshot, 0.0)
        authority.record_snapshot_taken()
        self.assertLess(authority.time_since_last_snapshot, 1.0)

    def test_blast_radius_constraint_in_ticket(self) -> None:
        blast = BlastRadiusConstraint(
            max_requests_per_sec=50.0,
            max_total_requests=500,
            max_wall_clock_sec=15.0,
            allowed_endpoint_glob="/api/*",
        )
        req = ExecutionRequest(
            request_id="req-1",
            tenant_id="t-1",
            target=TargetSpec(host="example.com"),
            stage="active_scan",
        )
        ticket = AuthorizedExecutionTicket(
            ticket_id="tick-1",
            request_id="req-1",
            tenant_id="t-1",
            authorized_at=100.0,
            expires_at=200.0,
            nonce="n-1",
            signature="sig-1",
            request=req,
            blast_radius=blast,
        )
        data = ticket.to_dict()
        self.assertEqual(data["blast_radius"]["max_total_requests"], 500)

        restored = AuthorizedExecutionTicket.from_mapping(data)
        self.assertEqual(restored.blast_radius.max_requests_per_sec, 50.0)
        self.assertEqual(restored.blast_radius.allowed_endpoint_glob, "/api/*")

    def test_per_tenant_eventbus_isolation(self) -> None:
        bus = EventBus()
        t1_events = []
        t2_events = []

        bus.subscribe_tenant("tenant-1", EventType.STAGE_STARTED, lambda e: t1_events.append(e))
        bus.subscribe_tenant("tenant-2", EventType.STAGE_STARTED, lambda e: t2_events.append(e))

        # Emit for tenant-1
        with TenantContext.scope("tenant-1"):
            bus.emit(EventType.STAGE_STARTED, source="test", data={"tenant_id": "tenant-1"})

        self.assertEqual(len(t1_events), 1)
        self.assertEqual(len(t2_events), 0)


if __name__ == "__main__":
    unittest.main()

