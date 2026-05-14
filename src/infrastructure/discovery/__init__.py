"""mDNS-based P2P worker discovery for local-mesh orchestration.

Enables pipeline workers to automatically discover each other on the
local network without manual configuration of IP addresses or hostnames.
"""

from .mdns import WorkerDiscovery

__all__ = ["WorkerDiscovery"]
