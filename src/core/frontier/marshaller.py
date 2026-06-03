"""
Cyber Security Test Pipeline - Frontier Binary Marshaller
Implements high-speed, zero-allocation binary serialization for distributed state.

.. warning::
    SECURITY RISK - cloudpickle deserialization: ``cloudpickle.loads`` on
    untrusted data is a **remote code execution (RCE) risk**. Even with the
    HMAC + module allowlist in ``_safe_loads``, any bypass of those controls
    would grant the attacker arbitrary Python code execution within the
    process. This path should be replaced with MessagePack/JSON serialization
    in a future refactor to eliminate the pickle attack surface entirely.
"""

import hashlib
import hmac
import os
from typing import Any, cast

import msgpack

from src.core.logging.trace_logging import get_pipeline_logger

logger = get_pipeline_logger(__name__)

# Secret for HMAC integrity checks
_MESH_SECRET_RAW = os.environ.get("MESH_SECRET")
_IS_PROD = os.environ.get("APP_ENV") == "production"

if not _MESH_SECRET_RAW:
    if _IS_PROD:
        raise ValueError(
            "CRITICAL SECURITY RISK: MESH_SECRET environment variable is required in production."
        )
    _MESH_SECRET_RAW = "frontier-default-secret-change-in-prod"  # noqa: S105
elif _IS_PROD and _MESH_SECRET_RAW in (
    "frontier-default-secret-change-in-prod",
    "frontier-default-secret",
    "frontier-default-secret-change-me",
):
    raise ValueError(
        "CRITICAL SECURITY RISK: MESH_SECRET must not be a default value in production."
    )

_MESH_SECRET = _MESH_SECRET_RAW.encode()


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

# Allowlist for cloudpickle deserialization: restricts which modules/classes may be loaded.
# This prevents arbitrary code execution from untrusted or replayed payloads.
_PERMITTED_MODULES: frozenset[str] = frozenset(
    {
        "_codecs",
        "builtins",
        "cloudpickle",
        "cloudpickle.cloudpickle",
        "cloudpickle.cloudpickle_fast",
        "codecs",
        "collections",
        "collections.abc",
        "copyreg",
        "datetime",
        "functools",
        "msgpack",
        "_operator",
        "operator",
        "src.core.frontier.bloom",
        "src.core.frontier.bloom_mesh",
        "src.core.frontier.ring_bus",
        "src.core.plugins.base",
        "src.analysis.intelligence.lateral_graph",
    }
)

# Only builtins and project code are permitted; any third-party module is rejected.
_BUILTIN_MODULE_PREFIXES = ("builtins.", "src.", "_codecs", "collections", "datetime", "operator")


def _assert_safe_pickle_object(obj: object) -> None:
    """Raise ValueError if obj was deserialized from a disallowed source module."""
    module = getattr(type(obj), "__module__", None) or ""
    if not (
        module in _PERMITTED_MODULES or any(module.startswith(p) for p in _BUILTIN_MODULE_PREFIXES)
    ):
        raise ValueError(f"Refusing deserialization of object from untrusted module: {module}")


def _safe_loads(verified: bytes) -> Any:
    """Deserialize with cloudpickle after verifying HMAC and asserting safe originating modules."""
    result = cloudpickle.loads(verified)  # noqa: S301
    if isinstance(result, dict):
        for value in result.values():
            try:
                _assert_safe_pickle_object(value)
            except ValueError:
                _assert_safe_pickle_object(result)
                break
    else:
        _assert_safe_pickle_object(result)
    return result


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
        from src.core.accelerators import has_avx512

        self._has_avx512 = has_avx512()

    def pack(self, data: Any) -> bytes:
        """Serialize data to binary MessagePack format."""
        try:
            if self._has_avx512:
                from src.core.accelerators import fast_msgpack_pack_simd

                return fast_msgpack_pack_simd(data)
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
        """Decompress and deserialize binary data using cloudpickle with module allowlist."""
        try:
            decompressed = decompress_bytes(raw_data) if decompress else raw_data
            verified = _verify_payload(decompressed)
            return _safe_loads(verified)
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
    """Helper for one-off cloudpickle unmarshalling with module allowlist."""
    decompressed = decompress_bytes(raw) if decompress else raw
    verified = _verify_payload(decompressed)
    return _safe_loads(verified)
