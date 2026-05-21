import asyncio
import struct

import pytest

from src.core.frontier.ghost_actor import ScanActor
from src.core.frontier.proc_pool import FrontierProcessPool
from src.core.frontier.state import (
    CRDTCompactionBudget,
    NeuralState,
    radix_sort_timestamps,
)
from src.core.frontier.wal import FrontierWAL
from src.core.storage.bounded_compaction_store import BoundedCompactionStateStore
from src.core.storage.local_backends import LocalCheckpointStore


@pytest.mark.asyncio
async def test_actor_dehydrate_rehydrate():
    def dummy_logic(task_input, state):
        state["x"] = state.get("x", 0) + task_input.get("val", 1)
        return {"result": state["x"]}

    actor = ScanActor.start("test-actor-1", dummy_logic)
    actor.ask({"command": "execute", "input": {"val": 10}})

    # Test dehydrate
    payload = actor.ask({"command": "dehydrate"})
    assert isinstance(payload, bytes)

    # Stop actor
    actor.stop()

    # Rehydrate into a new actor instance
    new_actor = ScanActor.start("test-actor-2", dummy_logic)
    res = new_actor.ask({"command": "rehydrate", "payload": payload})
    assert res["status"] == "success"

    state_after = new_actor.proxy().state.get().copy()
    assert state_after["x"] == 10
    new_actor.stop()


@pytest.mark.asyncio
async def test_actor_cold_start_warm_rejoin():
    def dummy_logic(task_input, state):
        return {}

    actor = ScanActor.start("test-actor-3", dummy_logic)
    state = actor.proxy().state.get()
    state["y"] = 42

    # Dehydrate
    snapshot = actor.ask({"command": "dehydrate"})
    actor.stop()

    # Restart
    new_actor = ScanActor.start("test-actor-4", dummy_logic)
    # Replay deltas
    deltas = [
        {"id": "wal-1", "delta": {"subdomains": ["a.com"]}},
        {"id": "wal-2", "delta": {"urls": ["http://b.com"]}}
    ]
    new_actor.ask({"command": "cold_start", "snapshot": snapshot, "deltas": deltas})

    actor_state = new_actor.proxy().state.get()
    assert actor_state["y"] == 42
    assert "a.com" in actor_state["subdomains"]

    # Warm rejoin with new deltas
    new_deltas = [
        {"id": "wal-3", "delta": {"subdomains": ["c.com"]}}
    ]
    new_actor.ask({"command": "warm_rejoin", "deltas": new_deltas})
    actor_state = new_actor.proxy().state.get()
    assert "c.com" in actor_state["subdomains"]

    new_actor.stop()


def test_crdt_compaction_budget_aimd():
    budget = CRDTCompactionBudget(initial_budget_ms=10.0, target_elapsed_ms=5.0)
    # Elapsed > target => decrease
    budget.adjust(8.0)
    assert budget.budget_ms == 7.5

    # Elapsed <= target => increase
    budget.adjust(3.0)
    assert budget.budget_ms == 12.5


def test_radix_sort_timestamps_helper():
    items = [("a", 1500.5), ("b", 1200.0), ("c", 1800.1), ("d", 1200.0)]
    sorted_items = radix_sort_timestamps(items)
    assert [x[0] for x in sorted_items] == ["b", "d", "a", "c"]


def test_wal_dual_commit_and_integrity(tmp_path):
    run_id = "test-run-wal"
    wal = FrontierWAL(None, run_id)
    aof_file = tmp_path / f"local_wal_{run_id}.aof"
    wal._aof_path = aof_file

    stage = "subdomain_scan"
    delta = {"subdomains": ["example.com"]}
    tx_id = wal.log_delta(stage, delta)
    assert tx_id is not None

    # Verify AOF contains the record
    assert aof_file.exists()

    # Recover deltas
    recovered = wal.recover_deltas()
    assert len(recovered) == 1
    assert recovered[0]["stage"] == stage
    assert recovered[0]["delta"]["subdomains"] == ["example.com"]

    # Corrupt AOF file by appending invalid line
    with open(aof_file, "a") as f:
        f.write("{invalid json}\n")

    # Re-recover. Should ignore corrupted line
    recovered2 = wal.recover_deltas()
    assert len(recovered2) == 1

    # Cleanup AOF
    wal.cleanup()
    assert not aof_file.exists()


@pytest.mark.asyncio
async def test_proc_pool_execute_task_binary(monkeypatch):
    pool = FrontierProcessPool(pool_size=1)

    class MockProcess:
        pid = 9999
        returncode = None

        def __init__(self):
            self.stdin = asyncio.Queue()
            self.stdout = asyncio.Queue()

        def terminate(self):
            pass

    mock_proc = MockProcess()
    q_in = mock_proc.stdin
    q_out = mock_proc.stdout

    class MockStream:
        def __init__(self, q_in, q_out):
            self.q_in = q_in
            self.q_out = q_out

        def write(self, data):
            for byte in data:
                self.q_in.put_nowait(bytes([byte]))

        async def drain(self):
            pass

        async def readexactly(self, n):
            buf = b""
            for _ in range(n):
                buf += await self.q_out.get()
            return buf

    mock_proc.stdin = MockStream(q_in, q_out)
    mock_proc.stdout = MockStream(q_out, q_in)

    async def mock_create(*args, **kwargs):
        return mock_proc

    monkeypatch.setattr(asyncio, "create_subprocess_exec", mock_create)
    monkeypatch.setattr("os.killpg", lambda *args: None, raising=False)
    monkeypatch.setattr("os.getpgid", lambda *args: 1, raising=False)

    await pool.warm_pool("dummy_bin", [])

    async def worker_echo():
        # Read 4 bytes length
        len_bytes = b""
        for _ in range(4):
            len_bytes += await q_in.get()
        length = struct.unpack("!I", len_bytes)[0]
        # Read payload
        payload = b""
        for _ in range(length):
            payload += await q_in.get()
        # Echo length-prefixed payload back
        for b in len_bytes:
            q_out.put_nowait(bytes([b]))
        for b in payload:
            q_out.put_nowait(bytes([b]))

    loop = asyncio.get_running_loop()
    loop.create_task(worker_echo())

    task_input = {"echo": "hello_world"}
    result = await pool.execute_task_binary("dummy_bin", task_input)
    assert result == task_input

    await pool.cleanup()


def test_bounded_compaction_state_store(tmp_path):
    local_store = LocalCheckpointStore(tmp_path)
    budget = CRDTCompactionBudget(initial_budget_ms=10.0)
    bounded_store = BoundedCompactionStateStore(local_store, budget, max_tombstone_age_seconds=0.0)

    state = NeuralState()
    state.subdomains.add("a.com")
    state.subdomains.remove("a.com")
    bounded_store.write("run-123", 1, state.to_crdt_snapshot())

    latest = bounded_store.read_latest("run-123")
    assert latest is not None

    recovered_state = NeuralState.from_crdt_snapshot(latest)
    assert recovered_state.subdomains.tombstone_count == 0
