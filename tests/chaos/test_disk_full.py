import uuid
from unittest.mock import mock_open, patch

from src.core.frontier.wal import FrontierWAL


def test_wal_local_disk_full_resilience() -> None:
    """Chaos test: Verify WAL continues durably through Redis Stream events when local disk is full."""
    run_id = f"chaos_disk_{uuid.uuid4().hex[:8]}"

    # Mock Redis client so that Redis writes are healthy and successful
    from unittest.mock import MagicMock

    mock_client = MagicMock()
    mock_client.xadd.return_value = b"12345-0"  # Redis stream ID

    # Initialize WAL
    wal = FrontierWAL(redis_url="redis://localhost:6379/0", run_id=run_id)
    wal._client = mock_client
    wal._active = True

    # Use patch to intercept the built-in open() and raise OSError (ENOSPC: Disk full)
    with patch("builtins.open", mock_open()) as mock_file:
        mock_file.side_effect = OSError(28, "No space left on device")

        # 1. Log delta transaction
        # Local AOF write will raise OSError, but WAL catch-block handles it and logs to Redis
        entry_id = wal.log_delta("recon", {"finding": "exploit_1"})

        # 2. Verify that Redis xadd was still successfully executed
        assert entry_id == "12345-0"
        assert mock_client.xadd.called

    # Clean up files cleanly
    wal.cleanup()
