"""Coverage for Ghost-VFS path validation."""

from __future__ import annotations

import pytest

from src.core.frontier.vfs_paths import VFSPathMixin


class _VFS(VFSPathMixin):
    def check(self, path: str) -> str:
        return self._validate_path(path)


@pytest.mark.unit
@pytest.mark.parametrize(
    "path",
    [
        "",
        ".",
        "/",
        "/etc/passwd",
        "C:/windows",
        "foo/../bar",
        "..",
        "foo/bar/..",
        "foo/\x00bar",
        "foo\\..\\bar",
    ],
)
def test_validate_path_rejects_unsafe(path: str) -> None:
    with pytest.raises(ValueError, match="Invalid virtual path"):
        _VFS().check(path)


@pytest.mark.unit
def test_validate_path_normalizes_relative() -> None:
    vfs = _VFS()
    assert vfs.check("foo/bar") == "foo/bar"
    assert vfs.check("foo\\\\bar") == "foo/bar"
    assert vfs.check("foo/./bar") == "foo/bar"
    assert vfs.check("reports/2024/scan.json") == "reports/2024/scan.json"
