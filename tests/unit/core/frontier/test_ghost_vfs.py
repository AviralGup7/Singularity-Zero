import base64
import json
import time

import pytest

from src.core.frontier.ghost_vfs import GhostVFS, eBPFHookManager


def _envelope_salt(raw: bytes) -> str:
    text = raw.decode("utf-8")
    payload = base64.urlsafe_b64decode(text.split(":", 1)[1].encode("ascii"))
    return json.loads(payload.decode("utf-8"))["salt"]


def test_ghost_vfs_lifecycle():
    vfs = GhostVFS()
    vfs.write_file("test.txt", "hello world")
    assert "test.txt" in vfs.list_files()

    content = vfs.read_file("test.txt")
    assert content == b"hello world"

    vfs.self_destruct()
    assert "test.txt" not in vfs.list_files()

    with pytest.raises(RuntimeError, match="data plane has been purged"):
        vfs.read_file("test.txt")


def test_ghost_vfs_key_rotation():
    vfs = GhostVFS(rotation_interval_hours=0.0001)  # Very short interval
    vfs.write_file("data.bin", b"\x00\xff\xee")
    initial_key = vfs._key

    # Manual rotation
    vfs.rotate_key()
    assert vfs._key != initial_key
    assert vfs.read_file("data.bin") == b"\x00\xff\xee"

    # Proactive rotation on write
    vfs._last_rotation = 0  # Force timeout
    vfs.write_file("trigger.txt", "rotate me")
    assert "trigger.txt" in vfs.list_files()
    assert vfs.read_file("data.bin") == b"\x00\xff\xee"


def test_ghost_vfs_rotation_failure_handling():
    vfs = GhostVFS()
    vfs.write_file("good.txt", "essential data")
    vfs.write_file("bad.txt", "will fail")

    initial_key = vfs._key
    initial_aesgcm = vfs._aesgcm

    # Mock decryption failure of one file by corrupting its payload
    vfs._files["bad.txt"] = b"invalid payload that cannot be decrypted"

    with pytest.raises(RuntimeError, match="Key rotation aborted"):
        vfs.rotate_key()

    # Verify that the vault state is untouched and original key/aesgcm remains active
    assert vfs._key == initial_key
    assert vfs._aesgcm == initial_aesgcm

    # Verify we can still decrypt the uncorrupted file using the original key
    assert vfs.read_file("good.txt") == b"essential data"


def test_ghost_vfs_path_traversal_prevention(tmp_path):
    vfs = GhostVFS()

    # 1. Verify write_file rejects paths with directory traversal or absolute patterns
    with pytest.raises(ValueError, match="Invalid virtual path"):
        vfs.write_file("../traversal.txt", "hacked")

    with pytest.raises(ValueError, match="Invalid virtual path"):
        vfs.write_file("/absolute/path.txt", "hacked")

    # 2. Verify flush_to_disk handles path containment safely
    vfs.write_file("valid.txt", "safe data")

    # Manually bypass write_file sanity checks by directly writing to the in-memory dict
    # to simulate a legacy/compromised stage trying to traverse on flush
    vfs._files["../hacked.txt"] = vfs._files["valid.txt"]

    # Use a physical directory inside tmp_path
    disk_dir = tmp_path / "sandbox"
    disk_dir.mkdir()

    vfs.flush_to_disk(str(disk_dir), "some_master_key")

    # Assert valid.txt was written successfully
    assert (disk_dir / "valid.txt").exists()

    # Assert the traversal file did NOT escape the sandbox and was NOT written
    assert not (tmp_path / "hacked.txt").exists()
    assert not (disk_dir / "../hacked.txt").exists()


def test_ghost_vfs_canonicalizes_paths_and_rejects_hidden_traversal():
    vfs = GhostVFS()

    vfs.write_file(r"reports\summary.txt", "canonical")
    assert "reports/summary.txt" in vfs.list_files()
    assert r"reports\summary.txt" not in vfs.list_files()
    assert vfs.read_file("reports/summary.txt") == b"canonical"
    assert vfs.read_file(r"reports\summary.txt") == b"canonical"

    for bad_path in (
        "",
        ".",
        "../escape.txt",
        "safe/../escape.txt",
        r"safe\..\escape.txt",
        "C:relative.txt",
        "safe/\x00bad.txt",
    ):
        with pytest.raises(ValueError, match="Invalid virtual path"):
            vfs.write_file(bad_path, "blocked")


def test_ghost_vfs_roundtrip_persistence(tmp_path):
    vfs = GhostVFS()
    vfs.write_file("subdomains.txt", "admin.internal.net\napi.internal.net")
    vfs.write_file("reports/findings.json", '{"vuln": "SQLi"}')

    disk_dir = tmp_path / "scan_export"
    disk_dir.mkdir()

    master_key = "SuperSecretMasterKey123!"

    # 1. Flush to disk
    vfs.flush_to_disk(str(disk_dir), master_key)

    # 2. Verify physical files exist
    subdomains_file = disk_dir / "subdomains.txt"
    findings_file = disk_dir / "reports" / "findings.json"
    assert subdomains_file.exists()
    assert findings_file.exists()

    # Verify cryptographic layout: salt (16 bytes) + nonce (12 bytes) + ciphertext
    with open(subdomains_file, "rb") as f:
        content = f.read()
    assert len(content) > 28

    # Verify unique salts per file
    with open(findings_file, "rb") as f:
        findings_content = f.read()
    assert _envelope_salt(content) != _envelope_salt(findings_content)

    # 3. Create a fresh VFS instance and load from disk
    new_vfs = GhostVFS()
    new_vfs.load_from_disk(str(disk_dir), master_key)

    # Verify re-hydrated memory
    assert "subdomains.txt" in new_vfs.list_files()
    assert "reports/findings.json" in new_vfs.list_files()
    assert new_vfs.read_file("subdomains.txt") == b"admin.internal.net\napi.internal.net"
    assert new_vfs.read_file("reports/findings.json") == b'{"vuln": "SQLi"}'

    # 4. Verify path traversal protection during load_from_disk
    import unittest.mock as mock

    bad_vfs = GhostVFS()

    # Mock os.walk to simulate walking and finding a file outside commonpath
    with mock.patch("os.walk") as mock_walk:
        # root, dirs, files
        mock_walk.return_value = [
            (str(disk_dir), [], ["valid.txt"]),
            (str(tmp_path), [], ["outside.txt"]),  # outside of disk_dir
        ]

        # Write a valid file with path-bound AAD for the mocked walk.
        path_bound_vfs = GhostVFS()
        path_bound_vfs.write_file("valid.txt", "valid data")
        path_bound_vfs.flush_to_disk(str(disk_dir), master_key)

        bad_vfs.load_from_disk(str(disk_dir), master_key)

        # valid.txt should be loaded, but outside.txt should NOT be loaded
        assert "valid.txt" in bad_vfs.list_files()
        assert "outside.txt" not in bad_vfs.list_files()


def test_ghost_vfs_chunked_streaming():
    vfs = GhostVFS()
    path = "large_log.bin"
    chunks = [b"chunk number 1 data", b"second chunk data block", b"final block of information"]

    # 1. Write the stream of chunks
    vfs.write_file_stream(path, iter(chunks))
    assert path in vfs.list_files()

    # 2. Stream read back chunk by chunk
    retrieved_chunks = list(vfs.read_file_stream(path))
    assert retrieved_chunks == chunks

    # 3. Read back full content flatly
    assert vfs.read_file(path) == b"".join(chunks)

    # 4. Verify tamper resistance on chunk headers
    raw_payload = bytearray(vfs._files[path])

    # Modifying chunk length header to trigger length corruption error
    raw_payload[16] ^= 0xFF
    vfs._files[path] = bytes(raw_payload)
    with pytest.raises(
        ValueError,
        match="Ghost-VFS: Corrupt chunk payload|Ghost-VFS: Corrupt chunk length header|decryption failed",
    ):
        list(vfs.read_file_stream(path))


def test_ghost_vfs_policy_enforcement():
    # 1. Test analyst role (read-only)
    analyst_vfs = GhostVFS(principal="analyst")

    with pytest.raises(PermissionError, match="not allowed to write"):
        analyst_vfs.write_file("report.txt", "analyst comment")

    # 2. Test system role (allowed to read/write general paths, restricted on secrets/keys)
    system_vfs = GhostVFS(principal="system")
    system_vfs.write_file("scans/subdomains.txt", "subdomains info")
    assert system_vfs.read_file("scans/subdomains.txt") == b"subdomains info"

    # Allowed access to secrets by system role
    system_vfs.write_file("secrets/app.pem", "private certificate data")
    assert system_vfs.read_file("secrets/app.pem") == b"private certificate data"

    # Test audit role (read-only, restricted on secrets)
    audit_vfs = GhostVFS(principal="audit")
    # Manually inject secret into the storage layer
    audit_vfs._files["secrets/app.pem"] = system_vfs._files["secrets/app.pem"]

    with pytest.raises(PermissionError, match="not allowed to read"):
        audit_vfs.read_file("secrets/app.pem")

    # Secret directories are protected even when the file extension itself is not sensitive.
    audit_vfs._files["secrets/password.txt"] = system_vfs._files["scans/subdomains.txt"]
    with pytest.raises(PermissionError, match="not allowed to read"):
        audit_vfs.read_file("secrets/password.txt")


def test_ghost_vfs_delete_validates_policy_and_wipes_buffer():
    vfs = GhostVFS()
    vfs.write_file("volatile.txt", "erase me")
    raw_ref = vfs._files["volatile.txt"]
    assert any(raw_ref)

    vfs.delete_file("volatile.txt")

    assert "volatile.txt" not in vfs.list_files()
    assert all(byte == 0 for byte in raw_ref)

    with pytest.raises(ValueError, match="Invalid virtual path"):
        vfs.delete_file("../escape.txt")

    analyst_vfs = GhostVFS(principal="analyst")
    with pytest.raises(PermissionError, match="not allowed to delete"):
        analyst_vfs.delete_file("visible.txt")


def test_ghost_vfs_self_destruct_wipes_buffers_and_unpins(monkeypatch):
    calls = []

    monkeypatch.setattr(
        eBPFHookManager,
        "pin_memory",
        staticmethod(lambda address_space: calls.append(("pin", address_space))),
    )
    monkeypatch.setattr(
        eBPFHookManager,
        "unpin_memory",
        staticmethod(lambda address_space: calls.append(("unpin", address_space))),
    )

    vfs = GhostVFS()
    vfs.write_file("session.bin", b"sensitive")
    raw_ref = vfs._files["session.bin"]
    key_ref = vfs._key

    vfs.self_destruct()

    assert vfs.list_files() == []
    assert all(byte == 0 for byte in raw_ref)
    assert all(byte == 0 for byte in key_ref)
    assert vfs._memory_pinned is False
    assert [name for name, _ in calls] == ["pin", "unpin"]

    with pytest.raises(RuntimeError, match="data plane has been purged"):
        vfs.write_file("after-purge.txt", "must not resurrect")


def test_ghost_vfs_read_stream_uses_snapshot_when_file_is_deleted():
    vfs = GhostVFS()
    chunks = [b"alpha", b"beta"]
    vfs.write_file_stream("stream.log", iter(chunks))

    stream = vfs.read_file_stream("stream.log")
    vfs.delete_file("stream.log")

    assert list(stream) == chunks


def test_ghost_vfs_read_stream_close_wipes_derived_file_key():
    vfs = GhostVFS()
    vfs.write_file_stream("stream.log", iter([b"alpha", b"beta"]))

    stream = vfs.read_file_stream("stream.log")
    assert next(stream) == b"alpha"
    file_key = stream._file_key
    assert any(file_key)

    stream.close()

    assert all(byte == 0 for byte in file_key)
    assert list(stream) == []


def test_ghost_vfs_retention_policy():
    from src.core.frontier.policies import PolicyEngine

    vfs = GhostVFS()

    vfs.write_file("file1.txt", "short content")
    vfs.write_file("file2.txt", "another content")
    vfs.write_file("file3.txt", "third file")

    # Manually set distinct created_at to guarantee ordering
    vfs._file_metadata["file1.txt"]["created_at"] = time.time() - 100
    vfs._file_metadata["file2.txt"]["created_at"] = time.time() - 50
    vfs._file_metadata["file3.txt"]["created_at"] = time.time()

    assert len(vfs.list_files()) == 3

    # 1. Enforce count limit = 2
    engine = PolicyEngine(max_file_count=2, max_age_seconds=3600, max_total_bytes=10000)
    engine.enforce_retention(vfs)
    # The oldest file (file1.txt) should be pruned
    assert len(vfs.list_files()) == 2
    assert "file1.txt" not in vfs.list_files()

    # 2. Enforce total bytes limit
    engine_bytes = PolicyEngine(max_file_count=10, max_age_seconds=3600, max_total_bytes=50)
    engine_bytes.enforce_retention(vfs)
    assert len(vfs.list_files()) < 2
