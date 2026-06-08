import os
import sys

import pytest

from src.infrastructure.security.encryption import (
    SecretManager,
)

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from _security_base import SecurityTestBase


class TestSecretManager(SecurityTestBase):
    def test_get_secret(self) -> None:
        manager = SecretManager(self.security_config)
        os.environ["TEST_SECRET"] = "test-value"
        assert manager.get_secret("TEST_SECRET") == "test-value"
        del os.environ["TEST_SECRET"]

    def test_get_secret_default(self) -> None:
        manager = SecretManager(self.security_config)
        assert manager.get_secret("NONEXISTENT_SECRET", "default") == "default"

    def test_get_secret_required(self) -> None:
        manager = SecretManager(self.security_config)
        with pytest.raises(ValueError):
            manager.get_secret_required("NONEXISTENT_SECRET")

    def test_set_secret(self) -> None:
        manager = SecretManager(self.security_config)
        manager.set_secret("MY_SECRET", "value")
        assert manager.get_secret("MY_SECRET") == "value"

    def test_clear_cache(self) -> None:
        manager = SecretManager(self.security_config)
        manager.set_secret("MY_SECRET", "value")
        manager.clear_cache()
        assert manager.get_secret("MY_SECRET") is None

    def test_hash_secret(self) -> None:
        manager = SecretManager(self.security_config)
        hashed = manager.hash_secret("password123")
        assert ":" in hashed

    def test_verify_hashed_secret(self) -> None:
        manager = SecretManager(self.security_config)
        hashed = manager.hash_secret("password123")
        assert manager.verify_hashed_secret("password123", hashed) is True
        assert manager.verify_hashed_secret("wrong", hashed) is False
