"""Scoped Local Forward Proxy Guard for Subprocess Network Egress Isolation (Invariant I29).

Spins up a lightweight local forward proxy bound to localhost that validates all
HTTP/CONNECT outbound destination hostnames and IP addresses
against the active NetworkEgressFilter / ScopeToken.
"""

from __future__ import annotations

import logging
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any
from urllib.parse import urlparse

from src.sandbox.network_isolation import EgressViolationError, NetworkEgressFilter

logger = logging.getLogger(__name__)


class ScopedProxyHandler(BaseHTTPRequestHandler):
    """HTTP/HTTPS Proxy request handler validating egress against NetworkEgressFilter."""

    egress_filter: NetworkEgressFilter | None = None

    def log_message(self, format: str, *args: Any) -> None:
        pass

    def _check_destination(self, host: str, port: int | None = None) -> bool:
        if self.egress_filter is None:
            return True
        try:
            self.egress_filter.validate_destination_or_raise(host, port)
            return True
        except EgressViolationError:
            return False

    def do_CONNECT(self) -> None:
        """Handle HTTPS CONNECT tunnels."""
        host_port = self.path.split(":")
        host = host_port[0]
        port = int(host_port[1]) if len(host_port) > 1 else 443

        if not self._check_destination(host, port):
            self.send_error(
                403,
                f"EgressViolation: Out-of-scope destination blocked by I29 guard ({host}:{port})",
            )
            return

        try:
            upstream = socket.create_connection((host, port), timeout=10.0)
        except Exception as exc:
            self.send_error(502, f"Bad Gateway: {exc}")
            return

        self.send_response(200, "Connection Established")
        self.end_headers()

        conns = [self.connection, upstream]
        self.connection.setblocking(False)
        upstream.setblocking(False)

        import select

        while True:
            rlist, _, xlist = select.select(conns, [], conns, 10.0)
            if xlist or not rlist:
                break
            for r in rlist:
                other = upstream if r is self.connection else self.connection
                try:
                    data = r.recv(8192)
                    if not data:
                        return
                    other.sendall(data)
                except Exception:
                    return

    def do_GET(self) -> None:
        """Handle standard HTTP proxy GET requests."""
        parsed = urlparse(self.path)
        host = parsed.hostname or self.headers.get("Host", "").split(":")[0]
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        if not self._check_destination(host, port):
            self.send_error(
                403, f"EgressViolation: Out-of-scope destination blocked by I29 guard ({host})"
            )
            return

        self.send_error(501, "Direct HTTP proxy relay not supported; use CONNECT tunnel")


class ScopedProxyServer:
    """Context manager and controller for a temporary scoped localhost proxy."""

    def __init__(self, egress_filter: NetworkEgressFilter | None = None) -> None:
        self.egress_filter = egress_filter
        self._server: HTTPServer | None = None
        self._thread: threading.Thread | None = None
        self.port: int = 0

    def start(self) -> str:
        """Start the proxy server on an ephemeral loopback port and return the proxy URL."""

        class BoundHandler(ScopedProxyHandler):
            egress_filter = self.egress_filter

        self._server = HTTPServer(("127.0.0.1", 0), BoundHandler)
        self.port = self._server.server_port
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return f"http://127.0.0.1:{self.port}"

    def stop(self) -> None:
        """Shut down the proxy server."""
        if self._server:
            self._server.shutdown()
            self._server.server_close()
            self._server = None

    def __enter__(self) -> str:
        return self.start()

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.stop()
