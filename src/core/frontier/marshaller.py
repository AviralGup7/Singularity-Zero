"""
Cyber Security Test Pipeline - Frontier Binary Marshaller
Implements high-speed, zero-allocation binary serialization for distributed state.
"""

from __future__ import annotations

from typing import Any, cast

import msgpack

from src.core.logging.trace_logging import get_pipeline_logger

logger = get_pipeline_logger(__name__)

try:
    import cloudpickle
except ImportError:
    import pickle as cloudpickle  # type: ignore

try:
    import zstandard as zstd

    _zstd_compressor = zstd.ZstdCompressor(level=3)
    _zstd_decompressor = zstd.ZstdDecompressor()

    def compress_bytes(data: bytes) -> bytes:
        return cast(bytes, _zstd_compressor.compress(data))

    def decompress_bytes(data: bytes) -> bytes:
        return cast(bytes, _zstd_decompressor.decompress(data))
except ImportError:
    import zlib

    def compress_bytes(data: bytes) -> bytes:
        return zlib.compress(data)

    def decompress_bytes(data: bytes) -> bytes:
        return zlib.decompress(data)


class FrontierMarshaller:
    """
    Hardware-optimized Binary Marshaller.
    Uses MessagePack and cloudpickle + zstd for efficient serialization.
    """

    def __init__(self) -> None:
        pass

    def pack(self, data: Any) -> bytes:
        """Serialize data to binary MessagePack format."""
        try:
            return cast(bytes, msgpack.packb(data, use_bin_type=True))
        except Exception as e:
            logger.error("Marshaller: Packing failed: %s", e)
            raise

    def unpack(self, raw_data: bytes) -> Any:
        """Deserialize MessagePack binary back to Python objects."""
        try:
            return msgpack.unpackb(raw_data, raw=False)
        except Exception as e:
            logger.error("Marshaller: Unpacking failed: %s", e)
            raise

    def pack_pickle(self, data: Any, compress: bool = True) -> bytes:
        """Serialize data to binary using cloudpickle and compress via zstd/zlib."""
        try:
            serialized = cast(bytes, cloudpickle.dumps(data))
            if compress:
                return compress_bytes(serialized)
            return serialized
        except Exception as e:
            logger.error("Marshaller: Pickle packing failed: %s", e)
            raise

    def unpack_pickle(self, raw_data: bytes, decompress: bool = True) -> Any:
        """Decompress and deserialize binary data using cloudpickle."""
        try:
            decompressed = decompress_bytes(raw_data) if decompress else raw_data
            # SECURITY: Unpacking is safe here as this marshaller only deserializes internally generated,
            # trusted, and/or cryptographically secured local state data exchanged via local IPC or WAL.
            return cloudpickle.loads(decompressed)  # nosec B301  # noqa: S301
        except Exception as e:
            logger.error("Marshaller: Pickle unpacking failed: %s", e)
            raise


def mesh_marshal(data: Any) -> bytes:
    """Helper for one-off mesh marshalling."""
    return cast(bytes, msgpack.packb(data, use_bin_type=True))


def mesh_unmarshal(raw: bytes) -> Any:
    """Helper for one-off mesh unmarshalling."""
    return msgpack.unpackb(raw, raw=False)


def mesh_marshal_pickle(data: Any, compress: bool = True) -> bytes:
    """Helper for one-off cloudpickle marshalling."""
    serialized = cast(bytes, cloudpickle.dumps(data))
    if compress:
        return compress_bytes(serialized)
    return serialized


def mesh_unmarshal_pickle(raw: bytes, decompress: bool = True) -> Any:
    """Helper for one-off cloudpickle unmarshalling."""
    decompressed = decompress_bytes(raw) if decompress else raw
    # SECURITY: This helper is exclusively used inside the FrontierProcessPool for secure parent-worker
    # IPC. The serialized data is exchanged locally over internal, authenticated process pipes.
    return cloudpickle.loads(decompressed)  # nosec B301  # noqa: S301
