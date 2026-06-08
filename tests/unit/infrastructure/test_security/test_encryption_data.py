import os
import sys

import pytest

from src.infrastructure.security.encryption import (
    DataEncryptor,
    generate_fernet_key,
)

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from _security_base import SecurityTestBase


class TestDataEncryptor(SecurityTestBase):
    def test_encrypt_decrypt_string(self) -> None:
        key = generate_fernet_key()
        encryptor = DataEncryptor(key)
        encrypted = encryptor.encrypt("secret data")
        decrypted = encryptor.decrypt(encrypted)
        assert decrypted == "secret data"

    def test_encrypt_decrypt_dict(self) -> None:
        key = generate_fernet_key()
        encryptor = DataEncryptor(key)
        data = {"key": "value", "number": 42}
        encrypted = encryptor.encrypt_dict(data)
        decrypted = encryptor.decrypt_dict(encrypted)
        assert decrypted == data

    def test_encrypt_bytes(self) -> None:
        key = generate_fernet_key()
        encryptor = DataEncryptor(key)
        encrypted = encryptor.encrypt(b"binary data")
        decrypted = encryptor.decrypt_bytes(encrypted)
        assert decrypted == b"binary data"

    def test_empty_key_raises(self) -> None:
        with pytest.raises(ValueError):
            DataEncryptor("")

    def test_invalid_key_raises(self) -> None:
        with pytest.raises(ValueError):
            DataEncryptor("not-a-valid-fernet-key")
