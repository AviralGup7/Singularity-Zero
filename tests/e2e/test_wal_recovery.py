"""
E2E Test for WAL-based Ghost-Actor Recovery.
Verifies that actors can recover state from the Redis-backed WAL.
"""

import time

import pytest

from src.core.frontier.ghost_actor import ScanActor
from src.core.frontier.wal import FrontierWAL


class MockRedis:
    def __init__(self):
        self.stream = []

    def xadd(self, key, payload, maxlen=None):
        entry_id = f"{int(time.time() * 1000)}-{len(self.stream)}"
        self.stream.append((entry_id.encode(), payload))
        return entry_id.encode()

    def xrange(self, key, min="-", max="+", count=None):
        # Very simple mock xrange
        results = []
        for eid, payload in self.stream:
            if min != "-" and not (eid.decode() > min.lstrip("(")):
                continue
            results.append((eid, payload))
        return results

    def ping(self):
        return True


def dummy_logic(task_input, state):
    return {"status": "ok"}


@pytest.mark.asyncio
async def test_actor_wal_recovery(monkeypatch):
    # 1. Setup Mock Redis and WAL
    mock_redis = MockRedis()
    monkeypatch.setattr("redis.from_url", lambda *a, **k: mock_redis)

    run_id = "test-recovery-run"
    wal = FrontierWAL("redis://localhost", run_id)

    # 2. Log some deltas
    wal.log_delta("recon", {"discovered_urls": ["http://a.com"]})
    wal.log_delta("analysis", {"vulnerabilities": ["xss-1"]})

    # 3. Create Actor and Recover
    actor_id = "recovery-actor"
    actor = ScanActor.start(actor_id, dummy_logic)

    try:
        # Initial state should be empty
        state = actor.ask({"command": "_get_attribute", "name": "state"}, block=True)
        assert "discovered_urls" not in state

        # Trigger recovery
        deltas = wal.recover_deltas()
        assert len(deltas) == 2

        recovery_result = actor.ask({"command": "recover", "deltas": deltas}, block=True)
        assert recovery_result["status"] == "success"
        assert recovery_result["applied_count"] == 2

        # Verify state is recovered
        recovered_state = actor.ask({"command": "_get_attribute", "name": "state"}, block=True)
        assert "http://a.com" in recovered_state["discovered_urls"]
        assert "xss-1" in recovered_state["vulnerabilities"]

    finally:
        actor.stop()


@pytest.mark.asyncio
async def test_incremental_wal_recovery(monkeypatch):
    mock_redis = MockRedis()
    monkeypatch.setattr("redis.from_url", lambda *a, **k: mock_redis)

    wal = FrontierWAL("redis://localhost", "test-incremental")

    # Log first delta
    id1 = wal.log_delta("stage1", {"k1": "v1"})

    # Log second delta
    wal.log_delta("stage2", {"k2": "v2"})

    # Recover only after id1
    deltas = wal.recover_deltas(start_id=id1)
    assert len(deltas) == 1
    assert deltas[0]["delta"] == {"k2": "v2"}
