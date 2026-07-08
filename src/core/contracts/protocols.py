"""Cross-layer protocol definitions for dependency inversion.

Core modules define their required interfaces here. Infrastructure and
pipeline modules register concrete implementations at startup time,
preventing circular imports and layer violations.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class GhostVFSProtocol(Protocol):
    """Minimal interface for GhostVFS used by PolicyEngine.

    Core/frontier/policies.py depends on this protocol rather than the
    concrete infrastructure.frontier.ghost_vfs.GhostVFS class, preserving
    the dependency rule: core must not import infrastructure.
    """

    def list_files(self) -> Any:
        """Return an iterable of file paths in the VFS."""
        ...

    def delete_file(self, path: str) -> None:
        """Delete a file from the VFS."""
        ...

    @property
    def _file_metadata(self) -> dict[str, dict[str, Any]]:
        """Mapping of path -> metadata dict (must contain 'created_at')."""
        ...

    @property
    def _files(self) -> dict[str, bytes]:
        """Mapping of path -> encrypted bytes."""
        ...


@runtime_checkable
class ToolExecutorFactoryProtocol(Protocol):
    """Callable that returns a ThreadPoolExecutor for tool execution.

    Used by ExecutionService to avoid importing pipeline.services.tool_execution.
    """

    def __call__(self) -> Any:
        """Return a concurrent.futures.ThreadPoolExecutor."""
        ...
