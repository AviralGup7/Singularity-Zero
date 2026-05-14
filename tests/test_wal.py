import pytest
from unittest.mock import MagicMock
from src.core.frontier.wal import FrontierWAL

def test_wal_log_and_recover(monkeypatch):
    mock_redis = MagicMock()
    import msgpack
    dummy_item = {
        b"stage": b"test_stage",
        b"ts": b"123.45",
        b"delta": msgpack.packb({"key": "val"})
    }
    
    call_counts = {"xrange": 0}
    def mock_xrange(*args, **kwargs):
        call_counts["xrange"] += 1
        if call_counts["xrange"] == 1:
            return [(b"1-0", dummy_item)]
        return []
    mock_redis.xrange.side_effect = mock_xrange
    
    monkeypatch.setattr("redis.from_url", lambda *a, **k: mock_redis)
    
    wal = FrontierWAL("redis://localhost", "run_1")
    assert wal._active is True
    
    wal.log_delta("test_stage", {"key": "val"})
    assert mock_redis.xadd.called
    
    deltas = wal.recover_deltas()
    assert len(deltas) == 1
    assert deltas[0]["stage"] == "test_stage"
    assert deltas[0]["delta"] == {"key": "val"}
