import unittest

from src.infrastructure.security.auth import (
    PasswordHash,
)


class TestPasswordHash(unittest.TestCase):
    def test_create_and_verify(self) -> None:
        ph = PasswordHash.create("secure_password")
        assert ph.algorithm == "pbkdf2_sha256"
        assert ph.verify("secure_password") is True
        assert ph.verify("wrong_password") is False

    def test_different_passwords(self) -> None:
        ph1 = PasswordHash.create("password1")
        ph2 = PasswordHash.create("password1")
        assert ph1.salt != ph2.salt
