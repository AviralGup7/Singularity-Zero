"""
Cyber Security Test Pipeline - POSIX Shared Memory Manager
Implements zero-copy shared buffers for high-speed cross-process communication.
"""

from __future__ import annotations

import struct
from multiprocessing import shared_memory

from src.core.logging.trace_logging import get_pipeline_logger

logger = get_pipeline_logger(__name__)


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
        if offset + len(data) > self.size:
            raise ValueError("Data exceeds shared memory buffer size")
        self.shm.buf[offset : offset + len(data)] = data
        return len(data)

    def read(self, size: int, offset: int = 0) -> bytes:
        """Read bytes from the shared buffer."""
        if offset + size > self.size:
            raise ValueError("Read exceeds shared memory buffer size")
        return bytes(self.shm.buf[offset : offset + size])

    def close(self) -> None:
        self.shm.close()
        if self._owner:
            try:
                self.shm.unlink()
            except Exception:
                pass


class ZeroCopyRouter:
    """
    Routes MessagePack payloads through shared memory buffers
    to avoid heavy IPC serialization overhead.
    """

    def __init__(
        self, buffer_name: str = "frontier_ring_bus", buffer_size: int = 10 * 1024 * 1024
    ) -> None:
        self.buffer_name = buffer_name
        self.buffer_size = buffer_size
        self._shm: SharedMemoryBuffer | None = None

    def close(self) -> None:
        """Close the underlying SharedMemoryBuffer if initialized."""
        if self._shm is not None:
            self._shm.close()
            self._shm = None

    def _get_buffer(self, create: bool = False) -> SharedMemoryBuffer:
        if self._shm is None:
            self._shm = SharedMemoryBuffer(self.buffer_name, self.buffer_size, create=create)
        return self._shm

    def route_payload(self, payload: bytes) -> str:
        """Writes payload to shared memory and returns its location reference."""
        shm = self._get_buffer(create=True)
        # Format: [length (4 bytes)] [payload]
        header = struct.pack("!I", len(payload))
        shm.write(header + payload, offset=0)
        return f"shm://{self.buffer_name}@0"

    def retrieve_payload(self, location: str) -> bytes:
        """Reads payload from shared memory using a location reference."""
        if not location.startswith("shm://"):
            raise ValueError("Invalid location protocol")

        # Parse shm://name@offset
        name_part, offset_part = location[6:].split("@")
        shm = self._get_buffer(create=False)

        # Read header
        header = shm.read(4, offset=int(offset_part))
        length = struct.unpack("!I", header)[0]

        # Read payload
        return shm.read(length, offset=int(offset_part) + 4)
