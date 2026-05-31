import time

from src.core.frontier.state import (
    CRDTCompactionBudget,
    LWWset,
    NeuralState,
    VectorClock,
    compact_state,
)


def test_lwwset_remove_preserves_epoch_timestamp() -> None:
    """Regression test: timestamp=0.0 must not be treated as None.

    If a remove arrives with ts=0.0 (epoch) it should *not* override a later add.
    """

    lww: LWWset[str] = LWWset()
    lww.add("item", timestamp=1.0)

    # This should NOT delete the item because it is older than the add.
    lww.remove("item", timestamp=0.0)

    assert "item" in lww.to_set()


def test_lwwset_same_timestamp_remove_wins_and_converges() -> None:
    left: LWWset[str] = LWWset()
    right: LWWset[str] = LWWset()

    left.add("item", timestamp=1.0)
    right.remove("item", timestamp=1.0)

    left.merge(right)
    right.merge(left)

    assert "item" not in left.to_set()
    assert left.to_dict() == right.to_dict()


def test_lwwset_default_clock_observes_prior_explicit_clock() -> None:
    lww: LWWset[str] = LWWset()

    lww.add("item", timestamp=time.time() + 60.0)
    lww.remove("item")

    assert "item" not in lww.to_set()


def test_lwwset_defensively_copies_mutable_values() -> None:
    finding = {"id": "f1", "tags": ["initial"]}
    lww: LWWset[dict[str, object]] = LWWset()

    lww.add(finding, timestamp=1.0)
    finding["tags"].append("mutated")  # type: ignore[union-attr]
    exported = lww.values()
    exported[0]["tags"].append("external")  # type: ignore[union-attr]

    assert lww.values() == [{"id": "f1", "tags": ["initial"]}]


def test_vector_clock_detects_concurrent_missing_versions() -> None:
    left = VectorClock.from_dict({"a": 2})
    right = VectorClock.from_dict({"a": 1, "b": 2})

    assert not left.is_later_than(right)
    assert not right.is_later_than(left)


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


def test_neural_state_skips_malformed_string_members() -> None:
    state = NeuralState()

    state.apply_delta({"subdomains": ["ok.example", {"bad": "example"}], "urls": [123, "https://ok.test"]})

    assert state.get_snapshot()["subdomains"] == ["ok.example"]
    assert state.get_snapshot()["urls"] == ["https://ok.test"]


def test_crdt_snapshot_restore_skips_malformed_entries() -> None:
    restored = NeuralState.from_crdt_snapshot(
        {
            "sets": {
                "urls": {
                    "good": {
                        "v": "https://good.test",
                        "hlc": {"l": 1.0, "c": 0, "node": "a"},
                        "ts": 1.0,
                        "d": False,
                    },
                    "bad": {"ts": "not-a-float", "d": False},
                }
            },
            "last_wal_id": 123,
        }
    )

    assert restored.get_snapshot()["urls"] == ["https://good.test"]
    assert restored.last_wal_id is None


def test_neural_state_merge_keeps_later_wal_cursor_commutatively() -> None:
    left = NeuralState()
    right = NeuralState()
    left.apply_delta({"_wal_id": "10-1", "urls": ["https://left.test"]})
    right.apply_delta({"_wal_id": "10-2", "urls": ["https://right.test"]})

    left.merge(right)
    right.merge(left)

    assert left.last_wal_id == "10-2"
    assert right.last_wal_id == "10-2"


def test_neural_state_metadata_merge_converges_commutatively() -> None:
    left = NeuralState()
    right = NeuralState()
    left.metadata = {"owner": {"name": "alpha"}}
    right.metadata = {"owner": {"name": "beta"}, "region": "us"}

    left.merge(right)
    right.merge(left)

    assert left.metadata == right.metadata
    assert left.metadata == {"owner": {"name": "beta"}, "region": "us"}


def test_compact_state_budget_applies_across_all_sets() -> None:
    state = NeuralState()
    old_ts = time.time() - 100
    state.subdomains.add("old.example", timestamp=old_ts)
    state.subdomains.remove("old.example", timestamp=old_ts + 1)
    state.urls.add("https://old.test", timestamp=old_ts)
    state.urls.remove("https://old.test", timestamp=old_ts + 1)
    state.findings.add({"id": "old"}, timestamp=old_ts)
    state.findings.remove({"id": "old"}, timestamp=old_ts + 1)

    result = compact_state(
        state,
        CRDTCompactionBudget(initial_budget_ms=1000.0),
        max_tombstone_age_seconds=1.0,
    )

    assert result["subdomains"] == 1
    assert result["urls"] == 1
    assert result["findings"] == 1
