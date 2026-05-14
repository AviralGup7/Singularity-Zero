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
