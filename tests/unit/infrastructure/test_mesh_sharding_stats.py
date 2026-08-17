"""Regression: shard move accounting must compare per-target leaders."""

from __future__ import annotations

import pytest

from src.infrastructure.mesh.sharding import MeshShardManager, ShardNode


@pytest.mark.unit
def test_stats_counts_moved_keys_by_target_not_set_order() -> None:
    manager = MeshShardManager(replication_factor=2, rebalance_min_interval_seconds=0.0)
    manager.rebalance(
        ["alpha", "bravo", "charlie"],
        node_weights={"alpha": 1.0, "bravo": 1.0, "charlie": 1.0},
        node_regions={"alpha": "us", "bravo": "eu", "charlie": "ap"},
        force=True,
    )
    targets = [f"asset-{idx}" for idx in range(12)]
    first = {target: manager.get_shard_leader(target) for target in targets}
    assert all(leader in {"alpha", "bravo", "charlie"} for leader in first.values())
    manager.stats(sample_targets=targets)

    manager.rebalance(["alpha"], node_weights={"alpha": 1.0}, force=True)
    after = {target: manager.get_shard_leader(target) for target in targets}
    expected_moved = sum(1 for target in targets if first[target] != after[target])
    snapshot = manager.stats(sample_targets=targets)
    assert snapshot.last_target_sample_moved == expected_moved
    assert snapshot.node_count == 1
    assert snapshot.rebalance_count >= 2


@pytest.mark.unit
def test_region_preference_and_owned_shards() -> None:
    manager = MeshShardManager(rebalance_min_interval_seconds=0.0)
    manager.add_node("us-1", region="us")
    manager.add_node("eu-1", region="eu")
    assert manager.rebalance(force=True)
    local = manager.get_shard_leader("tenant-a", local_region="us")
    assert local == "us-1"
    mine = manager.get_my_shards("us-1", ["t1", "t2", "t3", "t4", "t5"])
    assert all(manager.get_shard_leader(item) == "us-1" for item in mine)
    assert manager.count_my_shards("missing", ["t1"]) == 0


@pytest.mark.unit
def test_schedule_rebalance_applies_on_maintenance() -> None:
    manager = MeshShardManager(rebalance_min_interval_seconds=30.0)
    manager.schedule_rebalance(["n1", "n2"], delay_seconds=0.0)
    assert manager.stats().pending_rebalance is True
    assert manager.run_maintenance() is True
    assert manager.get_shard_leader("k") in {"n1", "n2"}
    assert manager.run_maintenance() is False


@pytest.mark.unit
def test_shard_node_rejects_non_positive_weight() -> None:
    node = ShardNode(node_id="x", weight=0.0)
    assert node.weight == 1.0
    manager = MeshShardManager(rebalance_min_interval_seconds=0.0)
    manager.add_node("n1", weight=-3)
    manager.set_node_weight("n1", 0.0)
    manager.set_node_region("n1", "us-west")
    manager.remove_node("missing")
    assert manager.rebalance_for_new_assets(set()) is False
