import time
import unittest

from src.infrastructure.security.auth import (
    Session,
)


class TestSession(unittest.TestCase):
    def test_session_not_expired(self) -> None:
        session = Session(user_id="u1", expires_at=time.time() + 3600)
        assert session.is_expired is False
        assert session.is_active is True

    def test_session_expired(self) -> None:
        session = Session(user_id="u1", expires_at=time.time() - 10)
        assert session.is_expired is True
        assert session.is_active is False
