"""
Cyber Security Test Pipeline - POSIX Shared Memory Manager
Implements zero-copy shared buffers for high-speed cross-process communication.
"""

from __future__ import annotations

import struct
import threading
from multiprocessing import shared_memory
from typing import Any, cast

from src.core.logging.trace_logging import get_pipeline_logger

logger = get_pipeline_logger(__name__)


# Header layout (12 bytes total):
#   magic       (4s)        - 4-byte ASCII magic "FPSH"
#   version     (B)         - header format version (currently 1)
#   reserved    (3s)        - reserved padding
#   length      (I)         - payload length (network byte order)
_HEADER_FMT = "!4sB3sI"
_HEADER_SIZE = struct.calcsize(_HEADER_FMT)
_HEADER_MAGIC = b"FPSH"
_HEADER_VERSION = 1
_MAX_PAYLOAD_BYTES = 16 * 1024 * 1024  # 16 MiB per payload upper bound


class SharedMemoryBuffer:
    """Manages a named POSIX shared memory segment."""

    def __init__(self, name: str, size: int, create: bool = False) -> None:
        self.name = name
        self.size = size
        try:
            self.shm = shared_memory.SharedMemory(name=name, create=create, size=size)
            self._owner = create
        except Exception as e:
            logger.error("Failed to initialize shared memory %s: %s", name, e)
            raise

    def write(self, data: bytes, offset: int = 0) -> int:
        """Write bytes to the shared buffer."""
        if offset < 0 or offset + len(data) > self.size:
            raise ValueError("Data exceeds shared memory buffer size")
        buf = cast(Any, self.shm.buf)
        buf[offset : offset + len(data)] = data
        return len(data)

    def read(self, size: int, offset: int = 0) -> bytes:
        """Read bytes from the shared buffer."""
        if offset < 0 or offset + size > self.size:
            raise ValueError("Read exceeds shared memory buffer size")
        buf = cast(Any, self.shm.buf)
        return bytes(buf[offset : offset + size])

    def close(self) -> None:
        self.shm.close()
        if self._owner:
            try:
                self.shm.unlink()
            except Exception:  # noqa: S110
                pass


class ZeroCopyRouter:
    """
    Routes MessagePack payloads through shared memory buffers
    to avoid heavy IPC serialization overhead.

    Each payload is written at a monotonically increasing offset, with a
    structured 12-byte header carrying a magic identifier, format version,
    and payload length. Readers validate the magic and length to detect
    truncation or corruption. If the buffer would overflow, the offset
    counter wraps back to the start (overwriting the oldest payload).
    Callers MUST guarantee that only one payload is in-flight at a time
    on each router instance, or coordinate consumption externally.
    """

    def __init__(
        self, buffer_name: str = "frontier_ring_bus", buffer_size: int = 10 * 1024 * 1024
    ) -> None:
        self.buffer_name = buffer_name
        self.buffer_size = max(_HEADER_SIZE + 16, int(buffer_size))
        self._shm: SharedMemoryBuffer | None = None
        self._offset = 0
        self._lock = threading.Lock()

    def close(self) -> None:
        """Close the underlying SharedMemoryBuffer if initialized."""
        if self._shm is not None:
            self._shm.close()
            self._shm = None

    def _get_buffer(self, create: bool = False) -> SharedMemoryBuffer:
        if self._shm is None:
            self._shm = SharedMemoryBuffer(self.buffer_name, self.buffer_size, create=create)
        return self._shm

    def _align_offset(self, total: int) -> int:
        """Wrap the write offset back to the start when there is not enough room."""
        if self._offset + total > self.buffer_size:
            return 0
        return self._offset

    def route_payload(self, payload: bytes) -> str:
        """Writes payload to shared memory and returns its location reference.

        The location string encodes the buffer name, slot offset, payload
        length, and a monotonically increasing sequence number so readers
        can detect out-of-order or stale references.
        """
        if not isinstance(payload, (bytes, bytearray, memoryview)):
            raise TypeError("payload must be a bytes-like object")
        payload_bytes = bytes(payload)
        if len(payload_bytes) > _MAX_PAYLOAD_BYTES:
            raise ValueError(
                f"payload size {len(payload_bytes)} exceeds maximum {_MAX_PAYLOAD_BYTES} bytes"
            )
        header = struct.pack(
            _HEADER_FMT,
            _HEADER_MAGIC,
            _HEADER_VERSION,
            b"\x00\x00\x00",
            len(payload_bytes),
        )
        total = _HEADER_SIZE + len(payload_bytes)
        if total > self.buffer_size:
            raise ValueError("payload does not fit in shared memory buffer")

        shm = self._get_buffer(create=True)
        with self._lock:
            slot = self._align_offset(total)
            shm.write(header + payload_bytes, offset=slot)
            # Location format is ``shm://<name>@<offset>``. The payload length
            # is read from the in-buffer header on retrieval, so it does not
            # need to be encoded in the location string itself.
            location = f"shm://{self.buffer_name}@{slot}"
            self._offset = (slot + total) % self.buffer_size
        return location

    def retrieve_payload(self, location: str) -> bytes:
        """Reads payload from shared memory using a location reference.

        Validates the magic header and length to detect partial writes
        and corrupted buffers. The payload length is read from the
        in-buffer header (the canonical record), not the location string.
        """
        if not location.startswith("shm://"):
            raise ValueError("Invalid location protocol")
        try:
            rest = location[6:]
            # Accept both ``shm://name@<offset>`` and the legacy
            # ``shm://name@<offset>:<length>`` form for compatibility.
            name_part, meta = rest.split("@", 1)
            parts = meta.split(":", 1)
            offset = int(parts[0])
            declared_length = int(parts[1]) if len(parts) > 1 else 0
        except (ValueError, AttributeError) as exc:
            raise ValueError(f"Malformed SHM location reference: {location!r}") from exc

        if declared_length < 0 or declared_length > _MAX_PAYLOAD_BYTES:
            raise ValueError("Invalid payload length in SHM reference")

        if offset < 0 or offset + _HEADER_SIZE > self.buffer_size:
            raise ValueError("SHM offset out of bounds")

        shm = self._get_buffer(create=False)
        header = shm.read(_HEADER_SIZE, offset=offset)
        magic, version, _reserved, header_length = struct.unpack(_HEADER_FMT, header)
        if magic != _HEADER_MAGIC:
            raise ValueError("SHM header magic mismatch (data corrupted or not initialised)")
        if version != _HEADER_VERSION:
            raise ValueError(f"Unsupported SHM header version: {version}")
        # The in-buffer header is the canonical record of the payload
        # length. When the location string omits the length (the new
        # ``shm://name@<offset>`` form) we trust the header value
        # unconditionally. When the location string still carries a
        # length (the legacy ``shm://name@<offset>:<length>`` form) we
        # cross-check the two for early detection of corruption.
        if declared_length > 0 and header_length != declared_length:
            raise ValueError(
                f"SHM payload length mismatch: header says {header_length}, "
                f"reference says {declared_length}"
            )
        if header_length < 0 or header_length > _MAX_PAYLOAD_BYTES:
            raise ValueError("Invalid payload length in SHM header")
        if offset + _HEADER_SIZE + header_length > self.buffer_size:
            raise ValueError("Payload would overflow shared memory buffer")
        return shm.read(header_length, offset=offset + _HEADER_SIZE)
