"""
Cyber Security Test Pipeline - Frontier Binary Marshaller
Implements high-speed, zero-allocation binary serialization for distributed state.
"""

import hashlib
import hmac
import os
from typing import Any, cast

import msgpack

from src.core.logging.trace_logging import get_pipeline_logger

logger = get_pipeline_logger(__name__)

# Secret for HMAC integrity checks
_MESH_SECRET = os.environ.get("MESH_SECRET", "frontier-default-secret-change-in-prod").encode()


def _derive_integrity_key(salt: bytes) -> bytes:
    """Derive a one-time integrity key using HKDF-like approach."""
    return hmac.new(_MESH_SECRET, salt, hashlib.sha256).digest()


def _sign_payload(payload: bytes) -> bytes:
    """Attach an HMAC signature to the payload."""
    salt = os.urandom(16)
    key = _derive_integrity_key(salt)
    signature = hmac.new(key, payload, hashlib.sha256).digest()
    return salt + signature + payload


def _verify_payload(signed_payload: bytes) -> bytes:
    """Verify the HMAC signature and return the original payload.

    Raises:
        ValueError: If signature verification fails.
    """
    if len(signed_payload) < 48:  # 16 (salt) + 32 (sha256)
        raise ValueError("Invalid signed payload: too short")

    salt = signed_payload[:16]
    signature = signed_payload[16:48]
    payload = signed_payload[48:]

    key = _derive_integrity_key(salt)
    expected_signature = hmac.new(key, payload, hashlib.sha256).digest()

    if not hmac.compare_digest(signature, expected_signature):
        raise ValueError("Payload integrity check failed: signature mismatch")

    return payload


try:
    import cloudpickle
except ImportError:
    import pickle as cloudpickle  # type: ignore

_FORCE_ZLIB = False

try:
    import zstandard as zstd

    _zstd_compressor = zstd.ZstdCompressor(level=3)
    _zstd_decompressor = zstd.ZstdDecompressor()
    _HAS_ZSTD = True
except ImportError:
    _HAS_ZSTD = False


def compress_bytes(data: bytes) -> bytes:
    if _HAS_ZSTD and not _FORCE_ZLIB:
        return cast(bytes, _zstd_compressor.compress(data))
    import zlib
    return zlib.compress(data)


def decompress_bytes(data: bytes) -> bytes:
    if _HAS_ZSTD and not _FORCE_ZLIB:
        return cast(bytes, _zstd_decompressor.decompress(data))
    import zlib
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
            signed = _sign_payload(serialized)
            if compress:
                return compress_bytes(signed)
            return signed
        except Exception as e:
            logger.error("Marshaller: Pickle packing failed: %s", e)
            raise

    def unpack_pickle(self, raw_data: bytes, decompress: bool = True) -> Any:
        """Decompress and deserialize binary data using cloudpickle."""
        try:
            decompressed = decompress_bytes(raw_data) if decompress else raw_data
            verified = _verify_payload(decompressed)
            # SECURITY: Unpacking is safe here as this marshaller only deserializes internally generated,
            # trusted, and cryptographically verified local state data.
            return cloudpickle.loads(verified)  # nosec B301  # noqa: S301
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
    signed = _sign_payload(serialized)
    if compress:
        return compress_bytes(signed)
    return signed


def mesh_unmarshal_pickle(raw: bytes, decompress: bool = True) -> Any:
    """Helper for one-off cloudpickle unmarshalling."""
    decompressed = decompress_bytes(raw) if decompress else raw
    verified = _verify_payload(decompressed)
    # SECURITY: verified via HMAC signature before deserialization.
    return cloudpickle.loads(verified)  # nosec B301  # noqa: S301
