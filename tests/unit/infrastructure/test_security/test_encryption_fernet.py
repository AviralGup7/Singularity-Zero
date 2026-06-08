import unittest

from src.infrastructure.security.encryption import (
    generate_fernet_key,
)


class TestGenerateFernetKey(unittest.TestCase):
    def test_key_format(self) -> None:
        key = generate_fernet_key()
        assert isinstance(key, str)
        assert len(key) > 0

    def test_keys_are_unique(self) -> None:
        k1 = generate_fernet_key()
        k2 = generate_fernet_key()
        assert k1 != k2
