import unittest

from src.infrastructure.security.auth import (
    Role,
)


class TestRole(unittest.TestCase):
    def test_role_values(self) -> None:
        assert Role.ADMIN.value == "admin"
        assert Role.OPERATOR.value == "operator"
        assert Role.VIEWER.value == "viewer"

    def test_admin_permissions(self) -> None:
        perms = Role.ADMIN.permissions
        assert "jobs:create" in perms
        assert "users:read" in perms
        assert "config:update" in perms

    def test_operator_permissions(self) -> None:
        perms = Role.OPERATOR.permissions
        assert "jobs:create" in perms
        assert "users:read" not in perms
        assert "config:update" not in perms

    def test_viewer_permissions(self) -> None:
        perms = Role.VIEWER.permissions
        assert "jobs:read" in perms
        assert "jobs:create" not in perms

    def test_has_permission(self) -> None:
        assert Role.ADMIN.has_permission("jobs:create") is True
        assert Role.VIEWER.has_permission("jobs:create") is False
