import time
import unittest

from src.infrastructure.security.auth import (
    APIKey,
    Role,
)


class TestAPIKey(unittest.TestCase):
    def test_api_key_defaults(self) -> None:
        key = APIKey(user_id="u1", name="test", key_hash="a" * 64, key_prefix="csp_abc")
        assert key.is_active is True
        assert key.is_revoked is False
        assert key.role == Role.VIEWER

    def test_api_key_not_expired(self) -> None:
        key = APIKey(
            user_id="u1",
            name="test",
            key_hash="a" * 64,
            key_prefix="csp_abc",
            expires_at=time.time() + 3600,
        )
        assert key.is_expired is False

    def test_api_key_expired(self) -> None:
        key = APIKey(
            user_id="u1",
            name="test",
            key_hash="a" * 64,
            key_prefix="csp_abc",
            expires_at=time.time() - 10,
        )
        assert key.is_expired is True

    def test_api_key_valid(self) -> None:
        key = APIKey(
            user_id="u1",
            name="test",
            key_hash="a" * 64,
            key_prefix="csp_abc",
            expires_at=time.time() + 3600,
        )
        assert key.is_valid is True

    def test_api_key_invalid_revoked(self) -> None:
        key = APIKey(
            user_id="u1", name="test", key_hash="a" * 64, key_prefix="csp_abc", is_revoked=True
        )
        assert key.is_valid is False
