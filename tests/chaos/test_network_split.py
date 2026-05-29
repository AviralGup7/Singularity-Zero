from tests.stress.test_mesh_failover import dummy_logic

from src.core.frontier.ghost_actor import ScanActor


def test_network_split_and_crdt_heal_convergence() -> None:
    """Chaos test: Verify independent partitions accumulate state and reconcile deterministically when network heals."""
    # Let's instantiate a ScanActor running on a partitioned sub-mesh
    actor_ref = ScanActor.start(actor_id="split-actor", logic_fn=dummy_logic)

    try:
        # 1. Simulate active partition A: collects discoveries on targets in region A
        deltas_partition_a = [
            {"id": "wal-a1", "delta": {"findings": [{"id": "vuln-a", "severity": "high"}]}},
            {"id": "wal-a2", "delta": {"findings": [{"id": "vuln-b", "severity": "medium"}]}},
        ]

        # 2. Simulate active partition B: collects discoveries on targets in region B
        deltas_partition_b = [
            {
                "id": "wal-b1",
                "delta": {"findings": [{"id": "vuln-b", "severity": "medium"}]},
            },  # Overlapping finding
            {"id": "wal-c1", "delta": {"findings": [{"id": "vuln-c", "severity": "low"}]}},
        ]

        # 3. Apply partition A state updates
        actor_ref.ask({"command": "recover", "deltas": deltas_partition_a}, block=True)

        # 4. Apply partition B state updates (simulating network split healing and merging the state)
        actor_ref.ask({"command": "recover", "deltas": deltas_partition_b}, block=True)

        # 5. Retrieve final snapshot and assert conflict-free converged values
        snapshot = actor_ref.ask({"command": "snapshot"}, block=True)
        findings = snapshot.data["findings"]

        # Reconciled set size should be exactly 3 (vuln-a, vuln-b, vuln-c) with no duplicates
        assert len(findings) == 3

        finding_ids = {f["id"] for f in findings}
        assert finding_ids == {"vuln-a", "vuln-b", "vuln-c"}
    finally:
        actor_ref.stop()
