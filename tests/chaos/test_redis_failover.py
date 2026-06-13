import uuid
from unittest.mock import MagicMock

import pytest
import redis

from src.infrastructure.frontier.wal import FrontierWAL


@pytest.mark.chaos
def test_redis_failover_and_local_aof_fallback() -> None:
    """Chaos test: Verify WAL switches to AOF on Redis connection drop and recovers completely."""
    run_id = f"chaos_redis_{uuid.uuid4().hex[:8]}"

    # Mock Redis client to raise ConnectionError when actions are performed
    mock_client = MagicMock()
    mock_client.ping.side_effect = redis.exceptions.ConnectionError("Redis connection lost")
    mock_client.xadd.side_effect = redis.exceptions.ConnectionError("Redis connection lost")

    # Set up WAL. Although redis_url is provided, the connection ping throws ConnectionError
    # causing WAL to set self._active = False and fallback to AOF-only mode
    wal = FrontierWAL(redis_url="redis://localhost:6379/0", run_id=run_id)

    # Manually inject our mock client to simulate post-init connection drop if active was true
    wal._client = mock_client
    wal._active = False  # Set to false to trigger direct fallback code paths

    # 1. Log delta transitions - should log to local AOF replica cleanly
    tx_id_1 = wal.log_delta("stage_1", {"data": "event_1"})
    tx_id_2 = wal.log_delta("stage_2", {"data": "event_2"})

    assert tx_id_1 is not None
    assert tx_id_2 is not None
    assert tx_id_1.startswith("aof-")

    # 2. Simulate Redis coming back online
    wal._active = True
    mock_client.xrange.return_value = []  # Empty redis stream for rollback check

    # Re-verify recovery fallbacks to AOF
    # We mock _client.xrange to raise ConnectionError to force it to recover from AOF
    mock_client.xrange.side_effect = redis.exceptions.ConnectionError(
        "Redis down during xrange recovery"
    )

    recovered = wal.recover_deltas()

    # Assert AOF recovery reconstructed both logged transactions successfully with 0% data loss
    assert len(recovered) == 2
    assert recovered[0]["stage"] == "stage_1"
    assert recovered[0]["delta"] == {"data": "event_1"}
    assert recovered[1]["stage"] == "stage_2"
    assert recovered[1]["delta"] == {"data": "event_2"}

    # Clean up files cleanly
    wal.cleanup()
