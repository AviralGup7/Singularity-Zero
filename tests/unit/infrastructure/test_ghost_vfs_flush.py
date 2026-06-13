import os
import shutil
import tempfile

from src.infrastructure.frontier.ghost_vfs import GhostVFS
from src.infrastructure.security.encryption import Argon2idAESGCM


def test_ghost_vfs_flush_to_disk():
    # Setup
    vfs = GhostVFS()
    test_path = "target/run/test.txt"
    test_content = "secret data"
    vfs.write_file(test_path, test_content)

    export_dir = tempfile.mkdtemp()
    master_key = "my-master-password"

    try:
        # Execution
        vfs.flush_to_disk(export_dir, master_key)

        # Verification
        expected_file = os.path.join(export_dir, test_path)
        assert os.path.exists(expected_file)

        # Decrypt manually to verify the Argon2id/AES-GCM envelope
        with open(expected_file, "rb") as f:
            raw = f.read()

        decrypted = Argon2idAESGCM(master_key).decrypt(
            raw,
            f"ghost-vfs:{test_path}".encode(),
        )

        assert decrypted.decode() == test_content

    finally:
        shutil.rmtree(export_dir)


def test_ghost_vfs_flush_handles_multiple_files():
    vfs = GhostVFS()
    files = {
        "a.txt": "content a",
        "dir/b.json": '{"key": "value"}',
        "nested/deep/c.log": "log data",
    }
    for p, c in files.items():
        vfs.write_file(p, c)

    export_dir = tempfile.mkdtemp()
    master_key = "another-key"

    try:
        vfs.flush_to_disk(export_dir, master_key)

        for p, c in files.items():
            expected_file = os.path.join(export_dir, p)
            assert os.path.exists(expected_file)

            with open(expected_file, "rb") as f:
                raw = f.read()

            decrypted = Argon2idAESGCM(master_key).decrypt(
                raw,
                f"ghost-vfs:{p}".encode(),
            )
            assert decrypted.decode() == c

    finally:
        shutil.rmtree(export_dir)
