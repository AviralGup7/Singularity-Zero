"""mDNS-based P2P worker discovery."""

from typing import Any


class WorkerDiscovery:
    """mDNS worker discovery service."""

    def __init__(self, node_id: str, **kwargs: Any) -> None:
        self.node_id = node_id
        self.is_enabled = True

    async def start(self) -> None:
        """Start the mDNS discovery service."""

    async def stop(self) -> None:
        """Stop the mDNS discovery service."""
