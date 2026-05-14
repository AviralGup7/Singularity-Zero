"""mDNS-based P2P worker discovery for local-mesh orchestration.

Uses Zeroconf to register this worker as a service and discover other
workers on the local network.
"""

import logging
import socket
import time
from typing import Any

from zeroconf import ServiceBrowser, ServiceInfo, ServiceListener, Zeroconf

logger = logging.getLogger(__name__)

SERVICE_TYPE = "_cybersec-pipeline._tcp.local."


class WorkerListener(ServiceListener):
    """Listener for mDNS service events."""

    def __init__(self, callback: Any = None):
        self.callback = callback
        self.discovered_services: dict[str, dict[str, Any]] = {}

    def update_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        """Called when a service is updated."""
        info = zc.get_service_info(type_, name)
        if info:
            self._handle_service(info)

    def add_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        """Called when a service is added."""
        info = zc.get_service_info(type_, name)
        if info:
            self._handle_service(info)

    def remove_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        """Called when a service is removed."""
        if name in self.discovered_services:
            del self.discovered_services[name]
            logger.info("Worker service removed: %s", name)
            if self.callback:
                self.callback("remove", name)

    def _handle_service(self, info: ServiceInfo) -> None:
        """Extract metadata from ServiceInfo and store it."""
        name = info.name
        metadata = {}
        if info.properties:
            for k, v in info.properties.items():
                key = k.decode("utf-8") if isinstance(k, bytes) else str(k)
                val = v.decode("utf-8") if isinstance(v, bytes) else str(v)
                metadata[key] = val

        addresses = [socket.inet_ntoa(addr) for addr in info.addresses]

        self.discovered_services[name] = {
            "name": name,
            "addresses": addresses,
            "port": info.port,
            "metadata": metadata,
        }
        logger.info("Worker service discovered/updated: %s at %s:%d", name, addresses, info.port)
        if self.callback:
            self.callback("add", self.discovered_services[name])


class WorkerDiscovery:
    """Manages mDNS registration and discovery of pipeline workers.

    Allows workers to announce their presence and find peers on the
    local network for mesh orchestration.
    """

    def __init__(
        self,
        worker_id: str,
        port: int = 8008,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Initialize worker discovery.

        Args:
            worker_id: Unique identifier for this worker.
            port: Port the worker is listening on (for API/management).
            metadata: Additional key-value pairs to announce via mDNS.
        """
        self.worker_id = worker_id
        self.port = port
        self.metadata = metadata or {}
        self.zeroconf = Zeroconf()
        self.listener = WorkerListener(self._on_change)
        self.browser: ServiceBrowser | None = None
        self._known_workers: dict[str, dict[str, Any]] = {}

    def register(self) -> None:
        """Register this worker as an mDNS service."""
        local_ip = self._get_local_ip()
        info = ServiceInfo(
            SERVICE_TYPE,
            f"{self.worker_id}.{SERVICE_TYPE}",
            addresses=[socket.inet_aton(local_ip)],
            port=self.port,
            properties=self.metadata,
        )
        try:
            self.zeroconf.register_service(info)
            logger.info("Registered worker %s at %s:%d via mDNS", self.worker_id, local_ip, self.port)
        except Exception as exc:
            logger.error("Failed to register worker via mDNS: %s", exc)

    def start_discovery(self) -> None:
        """Start browsing for other workers on the local network."""
        self.browser = ServiceBrowser(self.zeroconf, SERVICE_TYPE, self.listener)
        logger.info("Started mDNS discovery for service type %s", SERVICE_TYPE)

    def discover(self, timeout: float = 2.0) -> list[dict[str, Any]]:
        """Find other workers and return their info.

        Args:
            timeout: Seconds to wait for discovery results.

        Returns:
            List of discovered worker information dictionaries.
        """
        if not self.browser:
            self.start_discovery()

        # Wait for some discovery results
        time.sleep(timeout)
        return list(self.listener.discovered_services.values())

    def _on_change(self, action: str, data: Any) -> None:
        """Callback for discovery events."""
        # This can be used to update internal state or trigger events
        pass

    def _get_local_ip(self) -> str:
        """Get the primary local IP address.

        Attempts to find the IP used for external traffic.
        """
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # doesn't even have to be reachable
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
        except Exception:
            ip = "127.0.0.1"
        finally:
            s.close()
        return ip

    def shutdown(self) -> None:
        """Unregister services and close Zeroconf."""
        try:
            if self.browser:
                self.browser.cancel()
            self.zeroconf.unregister_all_services()
            self.zeroconf.close()
            logger.info("mDNS discovery shut down")
        except Exception as exc:
            logger.error("Error during mDNS shutdown: %s", exc)
