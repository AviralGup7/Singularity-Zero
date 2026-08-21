from __future__ import annotations

import pytest

from src.auth import Capability, demo_session
from src.auth.rbac import PermissionError, can_launch, gaps, require


def test_analyst_can_launch() -> None:
    session = demo_session("Ada", "analyst")
    assert can_launch(session)
    require(session, Capability.VIEW_JOBS.value)


def test_viewer_cannot_manage_users() -> None:
    session = demo_session("V", "viewer")
    with pytest.raises(PermissionError):
        require(session, Capability.MANAGE_USERS.value)
    assert Capability.MANAGE_USERS.value in gaps(session, Capability.MANAGE_USERS.value)
