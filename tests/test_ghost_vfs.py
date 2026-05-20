import pytest

from src.core.frontier.ghost_vfs import GhostVFS


def test_ghost_vfs_lifecycle():
    vfs = GhostVFS()
    vfs.write_file("test.txt", "hello world")
    assert "test.txt" in vfs.list_files()

    content = vfs.read_file("test.txt")
    assert content == b"hello world"

    vfs.self_destruct()
    assert "test.txt" not in vfs.list_files()

    with pytest.raises(FileNotFoundError):
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

