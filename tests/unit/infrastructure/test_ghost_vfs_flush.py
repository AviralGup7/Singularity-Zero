import hashlib
import os
import shutil
import tempfile

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from src.core.frontier.ghost_vfs import GhostVFS


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

        # Decrypt manually to verify
        with open(expected_file, "rb") as f:
            raw = f.read()

        nonce = raw[:12]
        ciphertext = raw[12:]

        derived_key = hashlib.sha256(master_key.encode()).digest()
        aesgcm = AESGCM(derived_key)
        decrypted = aesgcm.decrypt(nonce, ciphertext, None)

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

            nonce = raw[:12]
            ciphertext = raw[12:]
            derived_key = hashlib.sha256(master_key.encode()).digest()
            decrypted = AESGCM(derived_key).decrypt(nonce, ciphertext, None)
            assert decrypted.decode() == c

    finally:
        shutil.rmtree(export_dir)
