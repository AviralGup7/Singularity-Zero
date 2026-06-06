"""Cyber Security Test Pipeline - Ghost-VFS Path Utilities
Path validation and normalization for the volatile virtual filesystem.
"""

from __future__ import annotations

import os
import posixpath


class VFSPathMixin:
    """Mixin providing path validation for GhostVFS."""

    def _validate_path(self, path: str) -> str:
        raw_path = os.fspath(path)
        if not isinstance(raw_path, str) or not raw_path:
            raise ValueError(f"Ghost-VFS: Invalid virtual path: {path}")
        if "\x00" in raw_path:
            raise ValueError(f"Ghost-VFS: Invalid virtual path: {path}")

        virtual_path = raw_path.replace("\\", "/")
        parts = virtual_path.split("/")
        cleaned_path = posixpath.normpath(virtual_path)
        if (
            cleaned_path in ("", ".")
            or ".." in parts
            or posixpath.isabs(cleaned_path)
            or cleaned_path.startswith("/")
            or (len(cleaned_path) > 1 and cleaned_path[1] == ":")
        ):
            raise ValueError(f"Ghost-VFS: Invalid virtual path: {path}")
        return cleaned_path
