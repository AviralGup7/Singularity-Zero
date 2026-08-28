"""Unit tests for Resilience & Observability (Items 19, 20, 21).

Verifies:
- Item 19: Per-endpoint circuit breaker reservation gating in HuntBudgetEnforcer.
- Item 20: P0 Emergency Ring Buffer spooling and overflow metric under disk write pressure.
- Item 21: GenerationalBloomFilter auto-rotation at measured FPR (0.005) and per-scan reset.
"""

from __future__ import annotations

import tempfile
import time
import unittest
from pathlib import Path

from src.core.frontier.bloom import GenerationalBloomFilter
from src.decision.hunt_budget import HuntBudget, HuntBudgetEnforcer
from src.infrastructure.security.audit import AuditEvent, AuditLogger, AuditSeverity
from src.infrastructure.security.config import SecurityConfig


class TestResilienceAndObservability(unittest.TestCase):
    def test_per_endpoint_circuit_breaker_gate(self) -> None:
        """Item 19: Breaker tripping on one endpoint only gates reservations targeting that endpoint."""
        enforcer = HuntBudgetEnforcer(budget=HuntBudget(max_requests=100))

        ep_flake = "https://flaky-target.internal:8443"
        ep_healthy = "https://healthy-target.internal:443"

        # Register breaker states
        is_flaky_open = True
        is_healthy_open = False

        enforcer.set_endpoint_reserve_gate(ep_flake, lambda: not is_flaky_open)
        enforcer.set_endpoint_reserve_gate(ep_healthy, lambda: not is_healthy_open)

        # Flaky endpoint reservations must be DENIED
        flaky_res = enforcer.reserve_with_identity(count=1, endpoint=ep_flake)
        self.assertIsNone(flaky_res)

        # Healthy endpoint reservations must SUCCEED
        healthy_res = enforcer.reserve_with_identity(count=1, endpoint=ep_healthy)
        self.assertIsNotNone(healthy_res)
        self.assertEqual(enforcer.reserved_requests, 1)

        # Non-specified endpoint falls back to global gate (allowed)
        unspecified_res = enforcer.reserve_with_identity(count=1, endpoint="https://other.internal")
        self.assertIsNotNone(unspecified_res)
        self.assertEqual(enforcer.reserved_requests, 2)

    def test_p0_emergency_ring_buffer_on_disk_pressure(self) -> None:
        """Item 20: Bounded emergency ring buffer preserves critical P0 audit entries under disk I/O failure."""
        with tempfile.TemporaryDirectory() as td:
            log_file = Path(td) / "audit_test.log"
            config = SecurityConfig()
            config.audit.log_path = str(log_file)

            logger = AuditLogger(config, emergency_ring_capacity=64)

            # Normal log write
            entry1 = logger.log(
                event=AuditEvent.SYSTEM_START,
                severity=AuditSeverity.INFO,
                details={"status": "normal"},
            )
            self.assertEqual(len(logger.get_emergency_ring_entries()), 0)

            # Simulate catastrophic disk failure by invalidating file handle
            logger._file_handle.close()
            logger._file_handle = None
            # Point to an invalid read-only or closed path simulation
            logger._ensure_log_file = lambda: None  # Prevent auto-reopen

            # Log P0 critical entry during disk failure
            crit_entry = logger.log(
                event=AuditEvent.AUTHZ_FAILURE,
                severity=AuditSeverity.CRITICAL,
                user_id="attacker",
                details={"reason": "unauthorized_admin_access"},
            )

            # Must be preserved in Emergency Ring Buffer
            spooled = logger.get_emergency_ring_entries()
            self.assertEqual(len(spooled), 1)
            self.assertEqual(spooled[0].event, AuditEvent.AUTHZ_FAILURE.value)
            self.assertEqual(spooled[0].severity, AuditSeverity.CRITICAL.value)

            # Overflow counter starts at 0
            self.assertEqual(logger.emergency_ring_overflow_count, 0)
            logger.close()

    def test_generational_bloom_measured_fpr_rotation_and_reset(self) -> None:
        """Item 21: Auto-rotation triggered by measured FPR estimation and per-scan reset."""
        bf = GenerationalBloomFilter(
            capacity=200,
            error_rate=0.001,
            max_fpr_threshold=0.005,
        )
        self.assertEqual(bf.generation, 1)

        # Initial measured FPR must be 0
        est_fpr = bf.estimate_runtime_fpr(sample_size=20)
        self.assertEqual(est_fpr, 0.0)

        # Populate filter to cause saturation
        for i in range(250):
            bf.add(f"item_{i}")

        # Auto-rotation must have triggered
        self.assertGreaterEqual(bf.generation, 2)

        # Reset per scan to prevent cross-run contamination
        bf.reset_scan()
        self.assertEqual(bf.generation, 1)
        self.assertFalse(bf.contains("item_0"))


if __name__ == "__main__":
    unittest.main()
