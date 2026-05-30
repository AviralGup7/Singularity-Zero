import time

from src.core.frontier.state import LWWset, NeuralState


def test_lwwset_remove_preserves_epoch_timestamp() -> None:
    """Regression test: timestamp=0.0 must not be treated as None.

    If a remove arrives with ts=0.0 (epoch) it should *not* override a later add.
    """

    lww: LWWset[str] = LWWset()
    lww.add("item", timestamp=1.0)

    # This should NOT delete the item because it is older than the add.
    lww.remove("item", timestamp=0.0)

    assert "item" in lww.to_set()


def test_neural_state_full_crdt_snapshot_preserves_tombstones_and_wal_cursor() -> None:
    state = NeuralState()
    state.apply_delta({"_wal_id": "1-0", "urls": ["https://a.test"], "findings": [{"id": "f1"}]})
    state.urls.remove("https://a.test", timestamp=time.time() + 1.0)

    restored = NeuralState.from_crdt_snapshot(state.to_crdt_snapshot())

    assert restored.last_wal_id == "1-0"
    assert "1-0" in restored.applied_wal_ids
    assert restored.urls.tombstone_count == 1
    assert restored.get_snapshot()["urls"] == []


def test_neural_state_replay_is_idempotent_for_duplicate_wal_ids() -> None:
    state = NeuralState()
    delta = {"_wal_id": "2-0", "findings": [{"id": "same", "title": "Same"}]}

    state.apply_delta(delta)
    state.apply_delta(delta)

    assert state.last_wal_id == "2-0"
    assert state.get_snapshot()["findings"] == [{"id": "same", "title": "Same"}]
