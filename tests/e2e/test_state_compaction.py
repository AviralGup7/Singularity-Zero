"""
E2E Test for CRDT State Compaction.
Verifies that old tombstones are pruned correctly without affecting visible state.
"""

import time

from src.core.frontier.state import LWWElement, NeuralState


def test_neural_state_compaction_logic():
    """Verify that NeuralState correctly prunes old tombstones across all sets."""
    state = NeuralState()

    # 1. Add some items
    state.subdomains.add("sub1.example.com")
    state.urls.add("https://example.com/api")
    state.findings.add({"id": "finding-1", "title": "Old Finding"})

    # 2. Remove them (creating tombstones)
    state.subdomains.remove("sub1.example.com")
    state.urls.remove("https://example.com/api")
    state.findings.remove({"id": "finding-1", "title": "Old Finding"})

    # Verify tombstones exist
    assert state.subdomains.tombstone_count == 1
    assert state.urls.tombstone_count == 1
    assert state.findings.tombstone_count == 1
    assert len(state.get_snapshot()["subdomains"]) == 0

    # 3. Compact with a large threshold (should purge nothing)
    stats = state.compact(max_tombstone_age_seconds=100)
    assert sum(stats.values()) == 0
    assert state.subdomains.tombstone_count == 1

    # 4. Manually backdate the tombstones for testing
    old_ts = time.time() - 500
    for lww in [state.subdomains, state.urls, state.findings]:
        for key in lww._elements:
            el = lww._elements[key]
            lww._elements[key] = LWWElement(
                value=el.value, hlc=el.hlc, vclock=el.vclock, timestamp=old_ts, deleted=True
            )

    # 5. Compact with a small threshold (should purge all tombstones)
    stats2 = state.compact(max_tombstone_age_seconds=10)
    assert stats2["subdomains"] == 1
    assert stats2["urls"] == 1
    assert stats2["findings"] == 1

    assert state.subdomains.tombstone_count == 0
    assert state.urls.tombstone_count == 0
    assert state.findings.tombstone_count == 0

    # 6. Verify visible state is still correct (empty)
    snapshot = state.get_snapshot()
    assert len(snapshot["subdomains"]) == 0
    assert len(snapshot["urls"]) == 0
    assert len(snapshot["findings"]) == 0


def test_compaction_preserves_new_items():
    """Verify that active items are never pruned by compaction."""
    state = NeuralState()

    # Add active item
    state.urls.add("https://active.com")

    # Manually backdate it (even if old, it's not a tombstone, so it should stay)
    el = state.urls._elements["https://active.com"]
    state.urls._elements["https://active.com"] = type(el)(
        value=el.value,
        hlc=el.hlc,
        vclock=el.vclock,
        timestamp=time.time() - 10000,
        deleted=False,
    )

    state.compact(max_tombstone_age_seconds=10)

    assert "https://active.com" in state.get_snapshot()["urls"]
    assert state.urls.tombstone_count == 0
