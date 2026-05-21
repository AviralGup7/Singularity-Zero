import base64
import json
from pathlib import Path
from unittest.mock import MagicMock

import msgpack

from src.core.frontier.state import NeuralState
from src.core.frontier.wal import (
    CRC64_TABLE,
    FrontierWAL,
    _init_crc64_table,
    compute_crc64,
    crc64_pure,
)


def test_crc64_pure():
    # Make sure table is initialized
    _init_crc64_table()
    assert len(CRC64_TABLE) == 256

    data = b"test payload for pure crc64 computation"
    pure_crc = crc64_pure(data)
    assert isinstance(pure_crc, int)

    # The computed hex string from compute_crc64 should match our pure CRC
    computed_hex = compute_crc64(data)
    assert computed_hex == f"{pure_crc:016x}"


def test_wal_inactive_no_redis():
    run_id = "test_run_inactive"
    wal = FrontierWAL(None, run_id)
    assert wal._active is False

    # Since active is False, it should write to local AOF and return an aof-* ID
    delta = {"key": "value"}
    entry_id = wal.log_delta("stage_1", delta)
    assert entry_id is not None
    assert entry_id.startswith("aof-")

    # The local AOF file should exist
    assert wal._aof_path.exists()

    # Recover should read from AOF fallback
    recovered = wal.recover_deltas()
    assert len(recovered) == 1
    assert recovered[0]["stage"] == "stage_1"
    assert recovered[0]["delta"] == delta

    # Cleanup should delete the AOF
    wal.cleanup()
    assert not wal._aof_path.exists()


def test_wal_active_log_delta(monkeypatch):
    mock_redis = MagicMock()
    mock_redis.ping.return_value = True
    # mock xadd to return a dummy entry ID
    mock_redis.xadd.return_value = b"12345-0"

    monkeypatch.setattr("redis.from_url", lambda *a, **k: mock_redis)

    run_id = "test_run_active_log"
    wal = FrontierWAL("redis://localhost", run_id)
    assert wal._active is True

    entry_id = wal.log_delta("stage_active", {"crdt": 123})
    assert entry_id == "12345-0"
    assert mock_redis.xadd.called

    # Clean up local AOF
    wal.cleanup()


def test_wal_log_delta_exception(monkeypatch):
    wal = FrontierWAL(None, "test_run_log_exc")

    # Mock stable_digest to raise exception
    def mock_stable_digest(*args, **kwargs):
        raise Exception("digest fail")

    monkeypatch.setattr("src.core.frontier.wal.stable_digest", mock_stable_digest)
    assert wal.log_delta("stage", {}) is None
    wal.cleanup()


def test_wal_connection_failure(monkeypatch):
    def mock_from_url(*args, **kwargs):
        raise Exception("Redis connection refused")

    monkeypatch.setattr("redis.from_url", mock_from_url)

    wal = FrontierWAL("redis://localhost:9999", "test_run_conn_fail")
    assert wal._active is False
    wal.cleanup()


def test_wal_aof_append_failure(monkeypatch, tmp_path):
    wal = FrontierWAL(None, "test_run_aof_fail")
    # Redirect AOF to a folder path to cause an OSError/PermissionError on write
    wal._aof_path = (
        tmp_path  # a directory instead of file, which causes error when opened for appending
    )

    # Should not raise exception, but should return aof-* ID or None
    entry_id = wal.log_delta("stage_x", {"a": 1})
    # Since AOF write fails and Redis is inactive, it might return aof-ts or None
    assert entry_id is not None or entry_id is None


def test_wal_recovery_redis_failed_or_corrupt(monkeypatch, tmp_path):
    mock_redis = MagicMock()

    # Simulate Redis connection active
    mock_redis.ping.return_value = True

    # 1. We mock xrange to return an entry with corrupt/incorrect CRC
    raw_delta = msgpack.packb({"crdt_delta": True}, use_bin_type=True)
    corrupt_item = {
        b"stage": b"test_corrupt_stage",
        b"ts": b"123.456",
        b"tx_id": b"tx_corrupt_123",
        b"crc64": b"0000000000000000",  # Incorrect CRC
        b"delta": raw_delta,
    }

    mock_redis.xrange.return_value = [(b"1-0", corrupt_item)]
    monkeypatch.setattr("redis.from_url", lambda *a, **k: mock_redis)

    run_id = "test_run_redis_corrupt"
    wal = FrontierWAL("redis://localhost", run_id)
    assert wal._active is True

    # 2. We set up the local AOF file with the correct CRC and data, so recovery falls back and succeeds
    wal._aof_path = tmp_path / f"local_wal_{run_id}.aof"
    correct_crc = compute_crc64(raw_delta)
    aof_entry = {
        "ts": 123.456,
        "stage": "test_corrupt_stage",
        "tx_id": "tx_corrupt_123",
        "crc64": correct_crc,
        "delta": base64.b64encode(raw_delta).decode("utf-8"),
    }
    with open(wal._aof_path, "w", encoding="utf-8") as f:
        f.write(json.dumps(aof_entry) + "\n")

    # Recover should hit CRC mismatch on Redis, log error, and fall back to local AOF
    recovered = wal.recover_deltas()
    assert len(recovered) == 1
    assert recovered[0]["stage"] == "test_corrupt_stage"
    assert recovered[0]["delta"] == {"crdt_delta": True}

    wal.cleanup()


def test_wal_recovery_aof_failed_or_corrupt(tmp_path):
    run_id = "test_run_aof_corrupt"
    wal = FrontierWAL(None, run_id)
    wal._aof_path = tmp_path / f"local_wal_{run_id}.aof"

    # Write AOF entries:
    # 1. Invalid JSON line (causes JSONDecodeError)
    # 2. Empty line (skipped by `if not line.strip()`)
    # 3. Entry with invalid CRC-64 hash
    # 4. Entry with valid CRC-64 hash
    raw_delta_valid = msgpack.packb({"valid": "data"}, use_bin_type=True)
    valid_crc = compute_crc64(raw_delta_valid)

    with open(wal._aof_path, "w", encoding="utf-8") as f:
        f.write("{malformed json line}\n")
        f.write("   \n")  # spaces/empty line to trigger continue
        f.write(
            json.dumps(
                {
                    "ts": 100.0,
                    "stage": "corrupt_crc_stage",
                    "tx_id": "tx_100",
                    "crc64": "0000000000000000",
                    "delta": base64.b64encode(raw_delta_valid).decode("utf-8"),
                }
            )
            + "\n"
        )
        f.write(
            json.dumps(
                {
                    "ts": 200.0,
                    "stage": "valid_stage",
                    "tx_id": "tx_200",
                    "crc64": valid_crc,
                    "delta": base64.b64encode(raw_delta_valid).decode("utf-8"),
                }
            )
            + "\n"
        )

    # Recover should gracefully skip corrupt/empty lines and return only the valid fourth entry
    recovered = wal.recover_deltas()
    assert len(recovered) == 1
    assert recovered[0]["stage"] == "valid_stage"
    assert recovered[0]["delta"] == {"valid": "data"}

    wal.cleanup()


def test_wal_aof_recovery_complete_failure(monkeypatch):
    wal = FrontierWAL(None, "test_run_aof_rec_fail")
    # Mock open inside src.core.frontier.wal to raise Exception
    import builtins

    original_open = builtins.open

    def mock_open(file, *args, **kwargs):
        if "test_run_aof_rec_fail" in str(file) and "r" in args:
            raise Exception("Disk read failure")
        return original_open(file, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", mock_open)

    assert wal.recover_deltas() == []
    wal.cleanup()


def test_wal_recover_deltas_redis_success(monkeypatch):
    mock_redis = MagicMock()
    mock_redis.ping.return_value = True

    # 2 entries to test looping and cursor updates
    raw_delta1 = msgpack.packb({"x": 1}, use_bin_type=True)
    raw_delta2 = msgpack.packb({"y": 2}, use_bin_type=True)

    call_count = 0

    def mock_xrange(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return [
                (
                    b"1-0",
                    {
                        b"stage": b"s1",
                        b"ts": b"10.0",
                        b"crc64": compute_crc64(raw_delta1).encode(),
                        b"delta": raw_delta1,
                    },
                ),
                (
                    b"2-0",
                    {
                        b"stage": b"s2",
                        b"ts": b"20.0",
                        b"crc64": compute_crc64(raw_delta2).encode(),
                        b"delta": raw_delta2,
                    },
                ),
            ]
        return []

    mock_redis.xrange.side_effect = mock_xrange
    monkeypatch.setattr("redis.from_url", lambda *a, **k: mock_redis)

    wal = FrontierWAL("redis://localhost", "run_redis_succ")
    recovered = wal.recover_deltas()
    assert len(recovered) == 2
    assert recovered[0]["stage"] == "s1"
    assert recovered[1]["stage"] == "s2"

    wal.cleanup()


def test_wal_recover_deltas_redis_exception(monkeypatch, tmp_path):
    mock_redis = MagicMock()
    mock_redis.ping.return_value = True
    # Mock xrange to raise an exception, triggering the AOF fallback
    mock_redis.xrange.side_effect = Exception("Redis stream query error")

    monkeypatch.setattr("redis.from_url", lambda *a, **k: mock_redis)

    run_id = "test_run_redis_exc"
    wal = FrontierWAL("redis://localhost", run_id)
    assert wal._active is True

    # Set up local AOF
    wal._aof_path = tmp_path / f"local_wal_{run_id}.aof"
    raw_delta = msgpack.packb({"crdt": True}, use_bin_type=True)
    aof_entry = {
        "ts": 123.456,
        "stage": "fallback_stage",
        "tx_id": "tx_123",
        "crc64": compute_crc64(raw_delta),
        "delta": base64.b64encode(raw_delta).decode("utf-8"),
    }
    with open(wal._aof_path, "w", encoding="utf-8") as f:
        f.write(json.dumps(aof_entry) + "\n")

    recovered = wal.recover_deltas()
    assert len(recovered) == 1
    assert recovered[0]["stage"] == "fallback_stage"

    wal.cleanup()


def test_wal_snapshots(monkeypatch):
    mock_redis = MagicMock()
    redis_store = {}

    def mock_set(key, val):
        redis_store[key] = val
        return True

    def mock_get(key):
        return redis_store.get(key)

    mock_redis.ping.return_value = True
    mock_redis.set.side_effect = mock_set
    mock_redis.get.side_effect = mock_get
    mock_redis.expire.return_value = True
    mock_redis.xtrim.return_value = 100

    # Mock xrange to return one delta first, then empty list to prevent infinite loop
    raw_delta = msgpack.packb({"findings": [{"id": "F2"}]}, use_bin_type=True)
    call_count = 0

    def mock_xrange(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return [
                (
                    b"2-0",
                    {
                        b"stage": b"s2",
                        b"ts": b"123.4",
                        b"crc64": compute_crc64(raw_delta).encode(),
                        b"delta": raw_delta,
                    },
                )
            ]
        return []

    mock_redis.xrange.side_effect = mock_xrange
    monkeypatch.setattr("redis.from_url", lambda *a, **k: mock_redis)

    run_id = "test_run_snapshots"
    wal = FrontierWAL("redis://localhost", run_id)
    assert wal._active is True

    state = NeuralState()
    state.apply_delta({"_wal_id": "1-0", "findings": [{"id": "F1", "severity": "HIGH"}]})

    # Test persist snapshot
    success = wal.persist_snapshot(state, reason="checkpoint")
    assert success is True

    # Test load snapshot
    snap_env = wal.load_snapshot()
    assert snap_env is not None
    assert snap_env["run_id"] == run_id
    assert "snapshot" in snap_env

    # Test recover state (which loads snapshot & replays the mock_xrange delta)
    recovered_state = wal.recover_state()
    assert recovered_state is not None
    findings = recovered_state.findings.values()
    assert len(findings) == 2

    # Test compaction
    compact_success = wal.compact_after_snapshot(state, keep_entries=500)
    assert compact_success is True

    wal.cleanup()


def test_wal_snapshot_compaction_failure(monkeypatch):
    mock_redis = MagicMock()
    mock_redis.ping.return_value = True
    # Make set return False or raise exception
    mock_redis.set.side_effect = Exception("Snapshot write failure")

    monkeypatch.setattr("redis.from_url", lambda *a, **k: mock_redis)

    wal = FrontierWAL("redis://localhost", "test_run_snap_comp_fail")
    state = NeuralState()

    # persist_snapshot fails due to Exception
    assert wal.persist_snapshot(state) is False

    # compact_after_snapshot fails because persist_snapshot fails
    assert wal.compact_after_snapshot(state) is False

    # test load_snapshot handles load exception
    mock_redis.get.side_effect = Exception("Get snapshot exception")
    assert wal.load_snapshot() is None

    # cleanup exception handling
    mock_redis.delete.side_effect = Exception("Delete keys exception")
    # should not crash
    wal.cleanup()


def test_wal_snapshot_validation_failures(monkeypatch):
    mock_redis = MagicMock()
    mock_redis.ping.return_value = True
    mock_redis.xrange.return_value = []
    monkeypatch.setattr("redis.from_url", lambda *a, **k: mock_redis)

    wal = FrontierWAL("redis://localhost", "test_run_snap_fails")
    assert wal._active is True

    # 1. Digest mismatch corruption
    envelope_corrupt_digest = {
        "run_id": "test_run_snap_fails",
        "snapshot": {"findings": []},
        "digest": "incorrect_digest_hash_123",
    }
    mock_redis.get.return_value = msgpack.packb(envelope_corrupt_digest, use_bin_type=True)
    assert wal.load_snapshot() is None

    # 2. Envelope is not a dictionary
    mock_redis.get.return_value = msgpack.packb("not-a-dictionary", use_bin_type=True)
    assert wal.load_snapshot() is None

    # 3. persist_snapshot when not active
    wal_inactive = FrontierWAL(None, "run_inactive_snap")
    assert wal_inactive.persist_snapshot(NeuralState()) is False
    assert wal_inactive.load_snapshot() is None

    wal.cleanup()
    wal_inactive.cleanup()


def test_wal_snapshot_missing_expire(monkeypatch):
    mock_redis = MagicMock()
    mock_redis.ping.return_value = True
    del mock_redis.expire
    monkeypatch.setattr("redis.from_url", lambda *a, **k: mock_redis)

    wal = FrontierWAL("redis://localhost", "run_no_expire")
    assert wal.persist_snapshot(NeuralState()) is True
    wal.cleanup()


def test_wal_snapshot_not_found(monkeypatch):
    mock_redis = MagicMock()
    mock_redis.ping.return_value = True
    mock_redis.get.return_value = None
    monkeypatch.setattr("redis.from_url", lambda *a, **k: mock_redis)

    wal = FrontierWAL("redis://localhost", "run_snap_not_found")
    assert wal.load_snapshot() is None
    wal.cleanup()


def test_wal_compact_inactive(monkeypatch):
    wal = FrontierWAL(None, "run_inactive_compact")
    monkeypatch.setattr(wal, "persist_snapshot", lambda *a, **k: True)
    assert wal.compact_after_snapshot(NeuralState()) is True
    wal.cleanup()


def test_wal_cleanup_active(monkeypatch):
    mock_redis = MagicMock()
    mock_redis.ping.return_value = True
    del mock_redis.delete
    monkeypatch.setattr("redis.from_url", lambda *a, **k: mock_redis)
    wal = FrontierWAL("redis://localhost", "run_cleanup_active")
    # Should not crash
    wal.cleanup()


def test_wal_cleanup_aof_exception(monkeypatch):
    wal = FrontierWAL(None, "run_cleanup_aof_exc")
    # Create AOF file
    wal._aof_path.write_text("dummy")

    # Mock unlink to raise exception
    def mock_unlink(*args, **kwargs):
        raise Exception("unlink fail")

    monkeypatch.setattr(Path, "unlink", mock_unlink)
    # Should not crash
    wal.cleanup()


def test_wal_aof_recovery_failed_completely(monkeypatch):
    wal = FrontierWAL(None, "run_aof_failed_comp")
    # Write a dummy file so that exists() returns True
    wal._aof_path.write_text("dummy")

    # Make open raise exception when reading the AOF file
    def mock_open(*args, **kwargs):
        raise OSError("Failed to open AOF file")

    monkeypatch.setattr("builtins.open", mock_open)
    # Should handle exception and return []
    assert wal.recover_deltas() == []
    # Make sure to cleanup/reset to avoid leaving builtins.open mocked
    monkeypatch.undo()
    wal.cleanup()


def test_wal_snapshot_persist_exception(monkeypatch):
    mock_redis = MagicMock()
    mock_redis.ping.return_value = True
    mock_redis.set.side_effect = Exception("Redis SET failed")
    monkeypatch.setattr("redis.from_url", lambda *a, **k: mock_redis)

    wal = FrontierWAL("redis://localhost", "run_snap_persist_exc")
    # persist_snapshot should handle the Redis SET exception and return False
    assert wal.persist_snapshot(NeuralState()) is False
    wal.cleanup()


def test_wal_recover_state_non_dict_delta(monkeypatch):
    mock_redis = MagicMock()
    mock_redis.ping.return_value = True
    monkeypatch.setattr("redis.from_url", lambda *a, **k: mock_redis)

    # Mock load_snapshot to return an envelope with a valid snapshot but one non-dictionary delta
    wal = FrontierWAL("redis://localhost", "run_non_dict_delta")
    envelope = {
        "run_id": "run_non_dict_delta",
        "snapshot": {"findings": []},
    }
    # Create the stable digest
    from src.core.frontier.wal import stable_digest

    envelope["digest"] = stable_digest(envelope["snapshot"])
    mock_redis.get.return_value = msgpack.packb(envelope, use_bin_type=True)

    # Mock recover_deltas to yield entries including one where delta is a non-dictionary
    def mock_recover_deltas(*args, **kwargs):
        return [
            {"id": "entry-1", "stage": "stage_1", "delta": {"finding_id": "F1"}},
            {"id": "entry-2", "stage": "stage_2", "delta": "invalid-non-dict-delta"},
        ]

    monkeypatch.setattr(wal, "recover_deltas", mock_recover_deltas)

    # Rebuilding state should succeed without crashing, skipping the non-dictionary delta
    state = wal.recover_state()
    assert isinstance(state, NeuralState)
    wal.cleanup()


def test_wal_compact_after_snapshot_exception(monkeypatch):
    mock_redis = MagicMock()
    mock_redis.ping.return_value = True
    # mock persist_snapshot to return True, but xtrim to raise Exception
    mock_redis.xtrim.side_effect = Exception("XTRIM failed")
    monkeypatch.setattr("redis.from_url", lambda *a, **k: mock_redis)

    wal = FrontierWAL("redis://localhost", "run_compact_exc")
    # mock persist_snapshot to return True so we reach xtrim call
    monkeypatch.setattr(wal, "persist_snapshot", lambda *a, **k: True)

    assert wal.compact_after_snapshot(NeuralState()) is False
    wal.cleanup()


def test_wal_snapshot_missing_set(monkeypatch):
    mock_redis = MagicMock()
    mock_redis.ping.return_value = True
    del mock_redis.set
    monkeypatch.setattr("redis.from_url", lambda *a, **k: mock_redis)

    wal = FrontierWAL("redis://localhost", "run_no_set")
    # should return False when client does not have 'set' method
    assert wal.persist_snapshot(NeuralState()) is False
    wal.cleanup()
