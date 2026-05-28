import time
import pytest
from src.core.frontier.state import HybridLogicalClock, LWWset, LWWElement, VectorClock


def test_hlc_tick_sequencing() -> None:
    """Verify that physical time advances tick logic and logical counter scales for synchronous events."""
    hlc = HybridLogicalClock(physical_time=0.0, node_id="node-a")
    
    # Tick with same physical time raises logical counter
    t1 = 1000.0
    tick1 = hlc.tick(t1)
    assert tick1.physical_time == t1
    assert tick1.logical_counter == 0
    assert tick1.node_id == "node-a"

    tick2 = tick1.tick(t1)
    assert tick2.physical_time == t1
    assert tick2.logical_counter == 1

    # Tick with later physical time resets counter to 0
    t2 = 1001.0
    tick3 = tick2.tick(t2)
    assert tick3.physical_time == t2
    assert tick3.logical_counter == 0


def test_hlc_update_convergence() -> None:
    """Verify HLC preserves causality across distributed messages/states using update ticks."""
    local = HybridLogicalClock(physical_time=100.0, logical_counter=5, node_id="node-a")
    
    # 1. Remote physical time is later
    remote1 = HybridLogicalClock(physical_time=150.0, logical_counter=2, node_id="node-b")
    merged1 = local.update(remote1, now=120.0)
    # Merged physical must match the maximum physical seen: 150.0
    assert merged1.physical_time == 150.0
    assert merged1.logical_counter == 3  # remote logical counter + 1

    # 2. Remote physical time is identical, remote logical is higher
    remote2 = HybridLogicalClock(physical_time=100.0, logical_counter=10, node_id="node-b")
    merged2 = local.update(remote2, now=100.0)
    assert merged2.physical_time == 100.0
    assert merged2.logical_counter == 11

    # 3. Local physical is later than remote and now
    remote3 = HybridLogicalClock(physical_time=50.0, logical_counter=1, node_id="node-b")
    merged3 = local.update(remote3, now=80.0)
    assert merged3.physical_time == 100.0
    assert merged3.logical_counter == 6


def test_hlc_comparisons() -> None:
    """Verify is_later_than compares HLCs using standard logical clock tie-breakers."""
    h1 = HybridLogicalClock(100.0, 0, "node-a")
    h2 = HybridLogicalClock(100.0, 0, "node-b")
    h3 = HybridLogicalClock(100.0, 1, "node-a")
    h4 = HybridLogicalClock(101.0, 0, "node-a")

    # Physical time comparison
    assert h4.is_later_than(h1)
    assert not h1.is_later_than(h4)

    # Counter comparison
    assert h3.is_later_than(h1)
    assert not h1.is_later_than(h3)

    # Node ID tie-breaker
    assert h2.is_later_than(h1)
    assert not h1.is_later_than(h2)


def test_lwwset_merge_hlc() -> None:
    """Verify that LWWset uses HLC values to perform deterministic commutative merges."""
    set_a = LWWset[str]()
    set_b = LWWset[str]()

    hlc_a = HybridLogicalClock(100.0, 0, "node-a")
    hlc_b = HybridLogicalClock(100.0, 1, "node-b")

    # set_a adds item at t=100.0 (hlc_a)
    set_a.add("finding-1", timestamp=100.0, hlc=hlc_a)
    # set_b removes same item at identical physical time but with higher hlc counter (hlc_b)
    set_b.remove("finding-1", timestamp=100.0, hlc=hlc_b)

    # Merging set_b into set_a should result in the item being deleted because hlc_b > hlc_a
    set_a.merge(set_b)
    assert "finding-1" not in set_a.to_set()

    # Reversing adding a higher-hlc insert
    hlc_c = HybridLogicalClock(100.0, 2, "node-c")
    set_b.add("finding-1", timestamp=100.0, hlc=hlc_c)
    
    set_a.merge(set_b)
    assert "finding-1" in set_a.to_set()


def test_hlc_serialization() -> None:
    """Verify HLC converts cleanly to/from dictionaries for MessagePack state envelopes."""
    hlc = HybridLogicalClock(physical_time=123.456, logical_counter=8, node_id="node-xyz")
    serialized = hlc.to_dict()
    assert serialized == {"l": 123.456, "c": 8, "node": "node-xyz"}

    deserialized = HybridLogicalClock.from_dict(serialized)
    assert deserialized.physical_time == 123.456
    assert deserialized.logical_counter == 8
    assert deserialized.node_id == "node-xyz"
