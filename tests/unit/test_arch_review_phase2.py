"""Architecture review Phase-2 P0 smoke tests."""

from __future__ import annotations

import pytest


def test_raft_capability_matrix_prod_default_quorum_1():
    from src.core.frontier.raft_capabilities import (
        RaftDeploymentMode,
        assert_production_raft_claim,
        default_deployment_mode,
        raft_capability_report,
    )

    assert default_deployment_mode() is RaftDeploymentMode.SINGLE_NODE_QUORUM_1
    report = raft_capability_report()
    assert report["default_mode"] == "single_node_quorum_1"
    names = {c["name"] for c in report["capabilities"]}
    assert "single_node_propose_commit" in names
    assert "networked_multi_host_raft" in names
    prod = [c for c in report["capabilities"] if c["production_default"]]
    assert all(c["name"] == "single_node_propose_commit" or not c["name"].startswith("networked") for c in prod)
    with pytest.raises(RuntimeError):
        assert_production_raft_claim("active-active raft in production")


def test_partition_wal_replicator_stub_refuses():
    from src.infrastructure.frontier.replication import (
        PartitionWALReplicationNotReady,
        PartitionWALReplicator,
    )

    rep = PartitionWALReplicator()
    assert rep.caught_up(target_index=1) is False
    assert rep.status()["enabled"] is False
    with pytest.raises(PartitionWALReplicationNotReady):
        rep.replicate_range(from_index=0, to_index=10)


def test_snapshot_manifest_select_requires_binding():
    from src.core.frontier.snapshot_manifest import (
        SnapshotManifest,
        SnapshotSelectionError,
        select_snapshot,
    )

    key = b"test-manifest-key-32bytes-long!!"
    good = SnapshotManifest(
        snapshot_id="s2",
        wal_id="wal-a",
        commit_index=5,
        term=2,
        schema_version=1,
        content_digest="abc",
    ).sign(key)
    better = SnapshotManifest(
        snapshot_id="s3",
        wal_id="wal-a",
        commit_index=9,
        term=2,
        schema_version=1,
        content_digest="def",
    ).sign(key)
    unbound = SnapshotManifest(
        snapshot_id="s9",
        wal_id="",  # missing binding
        commit_index=99,
        term=9,
        schema_version=1,
        content_digest="zzz",
    ).sign(key)

    chosen = select_snapshot([good, better, unbound], verify_key=key)
    assert chosen.snapshot_id == "s3"
    assert chosen.commit_index == 9

    with pytest.raises(SnapshotSelectionError):
        select_snapshot([unbound], verify_key=key)

    # High index without valid signature must not win
    forged = SnapshotManifest(
        snapshot_id="evil",
        wal_id="wal-a",
        commit_index=10_000,
        term=99,
        schema_version=1,
        content_digest="evil",
        signature="deadbeef",
    )
    chosen2 = select_snapshot([good, forged], verify_key=key)
    assert chosen2.snapshot_id == "s2"
