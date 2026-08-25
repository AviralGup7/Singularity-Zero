"""Comprehensive unit test suite for the Planetary-Scale Architecture Suite."""

import time

from src.infrastructure.flow_control.bulkhead import BulkheadPool
from src.infrastructure.flow_control.circuit_breaker import CircuitBreaker, CircuitState

# 1. Flow Control
from src.infrastructure.flow_control.pid_controller import AdaptivePIDController, PIDTuning


class TestFlowControl:
    def test_pid_controller_adaptation(self):
        pid = AdaptivePIDController(PIDTuning(target_latency_ms=200.0))
        # High latency observation should reduce concurrency and increase delay
        conc1, delay1 = pid.observe(observed_latency_ms=800.0, error_occurred=True)
        assert conc1 <= 10
        assert delay1 >= 50.0

        # Fast latency observation should increase concurrency
        conc2, delay2 = pid.observe(observed_latency_ms=50.0, error_occurred=False)
        assert conc2 >= conc1

    def test_circuit_breaker_transitions(self):
        cb = CircuitBreaker(name="test_target", failure_threshold=0.5, min_samples=4)
        assert cb.state == CircuitState.CLOSED
        cb.record_failure()
        cb.record_failure()
        cb.record_failure()
        cb.record_failure()
        assert cb.state == CircuitState.OPEN
        assert cb.allow_request() is False

    async def test_bulkhead_isolation(self):
        pool = BulkheadPool(default_max_concurrent=2)
        part_a = pool.get_partition("https://host-a.com/api")
        _part_b = pool.get_partition("https://host-b.com/api")

        await part_a.acquire()
        part_a.release(success=True)
        assert part_a.circuit_breaker.state == CircuitState.CLOSED


# 2. Concurrency
from src.core.concurrency.ring_buffer import DisruptorRingBuffer


class TestRingBuffer:
    def test_ring_buffer_offer_and_drain(self):
        rb: DisruptorRingBuffer[str] = DisruptorRingBuffer(capacity_exponent=4)  # 16 slots
        assert rb.capacity == 16
        for i in range(10):
            assert rb.offer(f"item_{i}") is True
        assert rb.size() == 10

        batch = rb.drain_batch(max_items=5)
        assert len(batch) == 5
        assert batch == [f"item_{i}" for i in range(5)]
        assert rb.size() == 5


# 3. Distributed
from src.core.distributed.crdt import GCounter, ORSet
from src.core.distributed.vector_clock import CausalOrder, VectorClock


class TestDistributedPrimitives:
    def test_vector_clock_causality(self):
        v1 = VectorClock().increment("node_a")
        v2 = v1.increment("node_b")
        assert v1.compare(v2) == CausalOrder.BEFORE
        assert v2.compare(v1) == CausalOrder.AFTER

        v3 = v1.increment("node_c")
        assert v2.compare(v3) == CausalOrder.CONCURRENT

    def test_crdt_gcounter_merge(self):
        g1 = GCounter().increment("node_a", 5)
        g2 = GCounter().increment("node_b", 10)
        merged = g1.merge(g2)
        assert merged.value() == 15

    def test_crdt_orset_merge(self):
        s1: ORSet[str] = ORSet().add("target_1", "tag_1")
        s2: ORSet[str] = ORSet().add("target_2", "tag_2")
        merged = s1.merge(s2)
        assert merged.read() == {"target_1", "target_2"}
        removed = merged.remove_tag("tag_1")
        assert removed.read() == {"target_2"}


# 4. Formal LTL Verifier
from src.core.events.events import TargetDispatchedEvent
from src.core.formal.ltl_verifier import LTLRuntimeVerifier, LTLViolationError


class TestLTLVerifier:
    def test_ltl_safety_invariant(self):
        verifier = LTLRuntimeVerifier()
        # Invariant: Dispatched targets must never be example-forbidden.com
        verifier.add_safety_invariant(
            name="ScopeGuard",
            predicate=lambda ev: "forbidden.com" not in getattr(ev, "url", ""),
            failure_message="Dispatched forbidden URL",
        )
        safe_ev = TargetDispatchedEvent(url="https://allowed.com/api", worker_id="w-1")
        verifier.verify_event(safe_ev)

        threw = False
        bad_ev = TargetDispatchedEvent(url="https://forbidden.com/api", worker_id="w-1")
        try:
            verifier.verify_event(bad_ev)
        except LTLViolationError:
            threw = True
        assert threw is True


# 5. Security: Macaroons
from src.core.security.macaroon import MacaroonMinter


class TestMacaroons:
    def test_macaroon_mint_attenuate_and_verify(self):
        minter = MacaroonMinter(root_key=b"super_secret_master_key_32_bytes")
        token = minter.mint("scanner_engine", "session_123")

        # Valid context
        assert minter.verify(token, {}) is True

        # Attenuate domain caveat
        attenuated = token.attenuate("allowed_domain = target.com")
        assert minter.verify(attenuated, {"domain": "api.target.com"}) is True
        assert minter.verify(attenuated, {"domain": "attacker.com"}) is False

        # Expiration caveat
        expiring = attenuated.attenuate(f"expires_before = {time.time() + 100}")
        assert minter.verify(expiring, {"domain": "target.com"}) is True
