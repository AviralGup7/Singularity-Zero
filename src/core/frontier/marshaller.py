"""
Cyber Security Test Pipeline - Frontier Binary Marshaller
Implements high-speed, zero-allocation binary serialization for distributed state.
"""

from __future__ import annotations

import logging
from typing import Any

import msgpack

from src.core.logging.trace_logging import get_pipeline_logger

logger = get_pipeline_logger(__name__)

class FrontierMarshaller:
    """
    Hardware-optimized Binary Marshaller.
    Uses MessagePack for efficient serialization of complex security findings and state.
    """
    def __init__(self) -> None:
        pass

    def pack(self, data: Any) -> bytes:
        """Serialize data to binary MessagePack format."""
        try:
            # Fix #212: Use stateless packb for thread-safety
            return msgpack.packb(data, use_bin_type=True)
        except Exception as e:
            logger.error("Marshaller: Packing failed: %s", e)
            raise

    def unpack(self, raw_data: bytes) -> Any:
        """Deserialize MessagePack binary back to Python objects."""
        try:
            # Fix #213: Raise exception instead of returning None
            return msgpack.unpackb(raw_data, raw=False)
        except Exception as e:
            logger.error("Marshaller: Unpacking failed: %s", e)
            raise

def mesh_marshal(data: Any) -> bytes:
    """Helper for one-off mesh marshalling."""
    return msgpack.packb(data, use_bin_type=True)

def mesh_unmarshal(raw: bytes) -> Any:
    """Helper for one-off mesh unmarshalling."""
    return msgpack.unpackb(raw, raw=False)
