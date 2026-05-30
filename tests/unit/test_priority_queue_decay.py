import time

from src.decision.priority_queue import CorrelationPriorityQueue, ScanTarget


def test_priority_queue_aging_bonus() -> None:
    """Verify that ScanTarget effective_priority increases monotonically over time (aging)."""
    target = ScanTarget(url="http://example.com/aging", base_priority=10.0, current_priority=10.0)

    # Set created_at to 10 seconds ago
    target.created_at = time.time() - 10.0

    # Effective priority should have a small aging bonus of ~10 * 0.01 = 0.1
    eff1 = target.effective_priority
    assert eff1 > 10.0
    assert abs(eff1 - 10.1) < 0.01

    # Set created_at to 100 seconds ago
    target.created_at = time.time() - 100.0
    eff2 = target.effective_priority
    assert eff2 > eff1
    assert abs(eff2 - 11.0) < 0.02


def test_priority_queue_boost_decay() -> None:
    """Verify that the boosted portion of ScanTarget decays exponentially over time."""
    target = ScanTarget(url="http://example.com/decay", base_priority=10.0, current_priority=10.0)

    # Apply boost
    target.apply_boost(factor=6.0, reason="cascade")

    # current_priority is capped at 50.0 since max(5*10, 50) = 50.0
    assert target.current_priority == 50.0

    # Immediate effective priority (time_since_boost = 0)
    eff_immediate = target.effective_priority
    assert abs(eff_immediate - 50.0) < 0.05

    # Simulate time passing by modifying last_boosted_at (exactly 120 seconds ago, i.e., 1 half-life)
    target.last_boosted_at = time.time() - 120.0

    # The boosted portion is 40.0 (50.0 - 10.0). After 1 half-life, it should decay by 50% to 20.0.
    # Plus aging bonus since it was created at the same time. Since created_at wasn't modified,
    # let's modify created_at to time.time() so there is no aging bonus.
    target.created_at = time.time()

    eff_decayed = target.effective_priority
    # Expected: base (10.0) + decayed boost (20.0) = 30.0
    assert abs(eff_decayed - 30.0) < 0.05

    # Verify aging + decayed boost combined
    target.created_at = time.time() - 100.0
    # Expected: base (10.0) + decayed boost (20.0) + aging (1.0) = 31.0
    assert abs(target.effective_priority - 31.0) < 0.05


def test_queue_pop_resolves_decay_and_aging() -> None:
    """Verify that popping from CorrelationPriorityQueue re-heapifies items using effective priority."""
    t1 = ScanTarget(url="http://example.com/t1", base_priority=10.0, current_priority=10.0)
    t2 = ScanTarget(url="http://example.com/t2", base_priority=5.0, current_priority=5.0)

    pq = CorrelationPriorityQueue([t1, t2])

    # Boost t2 massively so it gets higher priority than t1
    pq.boost_url("http://example.com/t2", factor=5.0, reason="urgent")

    # Immediate peek should return t2 (it was boosted to 25.0, t1 is 10.0)
    peeked = pq.peek()
    assert peeked is not None
    assert peeked.url == "http://example.com/t2"

    # Now simulate a massive decay on t2 boost (e.g. 600 seconds ago, 5 half-lives, so decayed to near 0)
    # And make t1 very old (created 2000 seconds ago) to simulate starvation
    t2.last_boosted_at = time.time() - 600.0
    t2.created_at = time.time()

    t1.created_at = time.time() - 2000.0

    # Now t1 effective priority should be 10.0 + 20.0 (aging) = 30.0
    # t2 effective priority should be 5.0 + decayed boost (~20.0 / 32 = 0.6) = ~5.6
    # So t1 should now be popped first!
    popped = pq.pop()
    assert popped is not None
    assert popped.url == "http://example.com/t1"
