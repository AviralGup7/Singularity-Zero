"""Cluster membership: join/leave/crash/rejoin and eventual agreement.

Invariant: after any finite mix of updates and merges, every replica
agrees on which workers are alive and which work each of them owns.
"""

from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor

import pytest

from src.infrastructure.mesh.gossip.models import MeshNode, mesh_node_from_mapping
from src.infrastructure.mesh.membership import ClusterMembership, MemberRecord, merge_member
from src.infrastructure.queue.coordinator import WorkerCoordinator
from src.infrastructure.queue.models import WorkerInfo


@pytest.mark.unit
def test_node_joins_and_is_alive() -> None:
    view = ClusterMembership(clock=lambda: 100.0)
    rec = view.join("w1", owned_work=["job-a"])
    assert rec.status == "alive"
    assert view.alive_ids() == {"w1"}
    assert view.work_owners() == {"job-a": "w1"}


@pytest.mark.unit
def test_node_leaves_releases_work() -> None:
    view = ClusterMembership(clock=lambda: 1.0)
    view.join("w1", owned_work=["job-a", "job-b"])
    left = view.leave("w1", now=2.0)
    assert left is not None
    assert left.status == "left"
    assert left.owned_work == frozenset()
    assert view.alive_ids() == set()
    assert view.work_owners() == {}


@pytest.mark.unit
def test_node_crashes_orphans_work() -> None:
    view = ClusterMembership(clock=lambda: 1.0)
    view.join("w7", owned_work=["scan-long"])
    crashed = view.crash("w7", now=2.0)
    assert crashed is not None
    assert crashed.status == "dead"
    assert "w7" not in view.alive_ids()
    assert view.work_owners() == {}


@pytest.mark.unit
def test_node_rejoins_bumps_incarnation() -> None:
    view = ClusterMembership(clock=lambda: 1.0)
    first = view.join("w1", owned_work=["old-job"])
    view.crash("w1")
    again = view.rejoin("w1", owned_work=["new-job"], now=3.0)
    assert again.incarnation == first.incarnation + 1
    assert again.status == "alive"
    assert view.work_owners() == {"new-job": "w1"}
    assert "old-job" not in view.work_owners()


@pytest.mark.unit
def test_stale_membership_suspect_then_dead() -> None:
    clock = {"now": 100.0}
    view = ClusterMembership(clock=lambda: clock["now"])
    view.join("w-stale", owned_work=["j1"], now=100.0)
    clock["now"] = 150.0
    assert view.age_out(suspect_after=45.0, dead_after=90.0) == []
    assert view.get("w-stale") is not None
    assert view.get("w-stale").status == "suspect"
    assert view.work_owners() == {"j1": "w-stale"}
    clock["now"] = 200.0
    dead = view.age_out(suspect_after=45.0, dead_after=90.0)
    assert dead == ["w-stale"]
    assert view.get("w-stale").status == "dead"
    assert view.work_owners() == {}


@pytest.mark.unit
def test_duplicate_join_is_idempotent() -> None:
    view = ClusterMembership(clock=lambda: 10.0)
    first = view.join("w1", owned_work=["j1"])
    second = view.join("w1", owned_work=["j1"])
    assert first.node_id == second.node_id
    assert len(view.members()) == 1
    assert view.work_owners() == {"j1": "w1"}
    # Heartbeat without restating work must not drop ownership.
    view.join("w1")
    assert view.work_owners() == {"j1": "w1"}


@pytest.mark.unit
def test_concurrent_membership_updates_stay_consistent() -> None:
    view = ClusterMembership()

    def _worker(index: int) -> None:
        node = f"n{index % 5}"
        view.join(node, owned_work=[f"job-{index % 7}"])
        if index % 11 == 0:
            view.suspect(node)
        if index % 17 == 0:
            view.leave(node)
            view.rejoin(node, owned_work=[f"job-{index % 7}"])

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(_worker, range(80)))

    owners = view.work_owners()
    assert len(owners) == len(set(owners))
    alive = view.alive_ids()
    for work_id, owner in owners.items():
        assert owner in alive
        rec = view.get(owner)
        assert rec is not None
        assert work_id in rec.owned_work
    # No work claimed by two alive members.
    claimed: dict[str, str] = {}
    for rec in view.members().values():
        if rec.status not in {"alive", "suspect"}:
            assert rec.owned_work == frozenset()
            continue
        for work_id in rec.owned_work:
            assert work_id not in claimed
            claimed[work_id] = rec.node_id


@pytest.mark.unit
def test_partition_merge_agrees_on_alive_and_owners() -> None:
    left = ClusterMembership(clock=lambda: 1.0)
    right = ClusterMembership(clock=lambda: 1.0)
    left.join("a", owned_work=["w-a"], now=1.0)
    left.join("b", owned_work=["w-shared"], now=1.0)
    right.join("a", owned_work=["w-a"], now=1.0)
    right.join("c", owned_work=["w-c"], now=1.0)
    # Concurrent claim of the same work by a later incarnation on C.
    right.rejoin("b", owned_work=["w-shared"], now=5.0)

    merged_ab = left.merge(right)
    merged_ba = right.merge(left)
    assert merged_ab.alive_ids() == merged_ba.alive_ids() == {"a", "b", "c"}
    assert merged_ab.work_owners() == merged_ba.work_owners()
    assert merged_ab.work_owners()["w-shared"] == "b"
    assert merged_ab.work_owners()["w-a"] == "a"
    assert merged_ab.work_owners()["w-c"] == "c"


@pytest.mark.unit
def test_merge_member_failure_dominates_same_incarnation() -> None:
    alive = MemberRecord(node_id="n", incarnation=1, status="alive", version=2)
    dead = MemberRecord(node_id="n", incarnation=1, status="dead", version=1)
    merged = merge_member(alive, dead)
    assert merged.status == "dead"
    assert merged.owned_work == frozenset()


@pytest.mark.unit
def test_gossip_update_feeds_membership() -> None:
    from src.infrastructure.mesh.gossip.engine import GossipEngine

    local = MeshNode(id="local", host="127.0.0.1", port=8000)
    engine = GossipEngine(local, secret="test-secret")
    engine.update_node(
        {
            "id": "peer-1",
            "host": "10.0.0.2",
            "port": 8000,
            "status": "alive",
            "last_seen": 10.0,
            "owned_work": ["job-9"],
            "incarnation": 2,
        }
    )
    assert "peer-1" in engine.peers
    rec = engine.membership.get("peer-1")
    assert rec is not None
    assert rec.status == "alive"
    assert "job-9" in rec.owned_work
    engine.update_node(
        {
            "id": "peer-1",
            "host": "10.0.0.2",
            "port": 8000,
            "status": "dead",
            "last_seen": 11.0,
            "incarnation": 2,
        }
    )
    assert engine.membership.get("peer-1").status == "dead"
    assert engine.membership.work_owners() == {}


@pytest.mark.unit
def test_coordinator_sweep_updates_membership() -> None:
    now = 1_000.0
    live = WorkerInfo(
        id="w-live",
        phase="running",
        last_heartbeat=now - 5,
        active_jobs=["job-live"],
    )
    silent = WorkerInfo(
        id="w-gone",
        phase="running",
        last_heartbeat=now - 120,
        active_jobs=["job-gone"],
    )

    class _Queue:
        def __init__(self) -> None:
            self.workers = {live.id: live, silent.id: silent}
            self.released: list[tuple[str, str]] = []

        async def _list_workers(self) -> list[WorkerInfo]:
            return list(self.workers.values())

        async def release_lease(
            self, job_id: str, worker_id: str, lease_version: str | None = None
        ) -> bool:
            self.released.append((job_id, worker_id))
            return True

        def persist_worker(self, worker: WorkerInfo) -> None:
            self.workers[worker.id] = worker

    queue = _Queue()
    coordinator = WorkerCoordinator(queue, suspect_after=45, dead_after=90, clock=lambda: now)

    async def _run() -> None:
        report = await coordinator.sweep()
        assert "w-gone" in report.declared_dead
        assert coordinator.membership.get("w-live").status == "alive"
        assert coordinator.membership.work_owners()["job-live"] == "w-live"
        assert coordinator.membership.get("w-gone").status == "dead"
        assert "job-gone" not in coordinator.membership.work_owners()

    asyncio.run(_run())


@pytest.mark.unit
def test_mesh_node_from_mapping_ignores_unknown_keys() -> None:
    node = mesh_node_from_mapping(
        {
            "id": "n1",
            "host": "127.0.0.1",
            "port": 9,
            "owned_work": ["a"],
            "incarnation": "3",
            "extra_future_field": True,
        }
    )
    assert node.id == "n1"
    assert node.owned_work == ["a"]
    assert node.incarnation == 3
