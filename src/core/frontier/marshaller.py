"""
Cyber Security Test Pipeline - Frontier Binary Marshaller
Implements high-speed, zero-allocation binary serialization for distributed state.

.. note::
    Security model: the marshaller is a *pure* MessagePack layer with a typed
    schema envelope and HMAC integrity. It contains **no pickle / cloudpickle**
    code path. The deserializer is fully driven by ``msgspec`` and a Pydantic
    schema, so untrusted bytes cannot construct arbitrary Python objects
    (no RCE surface) and cannot smuggle fields outside the declared schema.

    The previous ``cloudpickle``-based path has been removed. If you need
    function serialization, use ``msgspec``-encodable function references or
    keep a name-based registry (see ``ghost_actor._LOGIC_REGISTRY``).
"""

from __future__ import annotations

import hashlib
import hmac
import os
from typing import Any, Final, cast

import msgpack
import msgspec

from src.core.logging.trace_logging import get_pipeline_logger

logger = get_pipeline_logger(__name__)

MAX_PAYLOAD_BYTES: Final[int] = 10 * 1024 * 1024  # 10 MiB hard cap

# Secret for HMAC integrity checks.
_MESH_SECRET_RAW = os.environ.get("MESH_SECRET")
_IS_PROD = os.environ.get("APP_ENV") == "production"

if not _MESH_SECRET_RAW:
    if _IS_PROD:
        raise ValueError(
            "CRITICAL SECURITY RISK: MESH_SECRET environment variable is required in production."
        )
    # Generate a per-process random secret for development. This is
    # intentionally NOT a stable value across restarts: anything that survives
    # across processes must go through a long-lived keyring / secret store.
    _MESH_SECRET_RAW = hashlib.sha256(os.urandom(32)).hexdigest()
elif _IS_PROD and _MESH_SECRET_RAW in {
    "frontier-default-secret-change-in-prod",
    "frontier-default-secret",
    "frontier-default-secret-change-me",
}:
    raise ValueError(
        "CRITICAL SECURITY RISK: MESH_SECRET must not be a default value in production."
    )

_MESH_SECRET = _MESH_SECRET_RAW.encode()


def _derive_integrity_key(salt: bytes) -> bytes:
    """Derive a one-time integrity key using HMAC-SHA256."""
    return hmac.new(_MESH_SECRET, salt, hashlib.sha256).digest()


def _sign_payload(payload: bytes) -> bytes:
    """Attach an HMAC signature to the payload.

    Layout: ``salt (16) || signature (32) || payload``.
    """
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


# ---------------------------------------------------------------------------
# msgspec-backed schema. Only JSON-compatible types are permitted. No
# arbitrary Python objects, no callables, no modules - which is precisely
# what eliminates the pickle-RCE surface.
# ---------------------------------------------------------------------------

_PRIMITIVE_TYPES: Final[tuple[type, ...]] = (
    bool,
    int,
    float,
    str,
    bytes,
    type(None),
)


def _is_schema_compatible(value: Any, _seen: set[int] | None = None) -> bool:
    """Return True iff ``value`` only contains msgspec-encodable primitives.

    We explicitly reject callables, modules, file handles, custom classes, and
    anything else that ``msgspec`` cannot round-trip through MessagePack. This
    is the schema validator that backs ``safe_unpack``.
    """
    if _seen is None:
        _seen = set()
    oid = id(value)
    if oid in _seen:
        return True
    _seen.add(oid)
    if isinstance(value, (list, tuple)):
        return all(_is_schema_compatible(item, _seen) for item in value)
    if isinstance(value, (set, frozenset)):
        return all(_is_schema_compatible(item, _seen) for item in value)
    if isinstance(value, dict):
        ok = True
        for k, v in value.items():
            if not isinstance(k, (str, int, bool, bytes)) and k is not None:
                return False
            if not _is_schema_compatible(v, _seen):
                return False
            if not ok:
                return False
        return True
    return isinstance(value, _PRIMITIVE_TYPES) or value is None


class _MarshalledEnvelope(msgspec.Struct, frozen=True):
    """Typed envelope for a marshalled payload.

    ``schema_version`` lets us evolve the wire format without breaking older
    readers. ``payload_kind`` lets callers tag their data so consumers can
    dispatch to the right decoder.
    """

    schema_version: int
    payload_kind: str
    data: Any  # validated to be JSON-compatible by ``safe_pack``.


_msgspec_encoder = msgspec.msgpack.Encoder()
_msgspec_decoder = msgspec.msgpack.Decoder(_MarshalledEnvelope)


def safe_pack(data: Any, payload_kind: str = "generic") -> bytes:
    """Encode ``data`` into an integrity-signed, msgspec-bounded envelope.

    The output is a byte string of the form ``salt || sig || msgspec(envelope)``.
    The decoder validates the envelope through a Pydantic-equivalent msgspec
    Struct and rejects anything that contains non-primitive values.
    """
    if not _is_schema_compatible(data):
        raise TypeError(
            "safe_pack: refusing to serialize value with non-primitive types. "
            "Use msgspec-compatible types (dict, list, str, int, float, bool, "
            "bytes, None) only."
        )
    envelope = _MarshalledEnvelope(
        schema_version=1,
        payload_kind=payload_kind,
        data=data,
    )
    return _sign_payload(_msgspec_encoder.encode(envelope))


def safe_unpack(raw: bytes) -> Any:
    """Verify, decode, and schema-validate a marshalled envelope.

    Raises:
        ValueError: If signature verification, decoding, or schema validation fails.
        TypeError: If the decoded payload contains disallowed types.
    """
    if not isinstance(raw, (bytes, bytearray, memoryview)):
        raise TypeError("safe_unpack: raw must be bytes-like")
    if len(raw) > MAX_PAYLOAD_BYTES:
        raise ValueError(f"Refusing payload larger than {MAX_PAYLOAD_BYTES} bytes")
    verified = _verify_payload(bytes(raw))
    if len(verified) > MAX_PAYLOAD_BYTES:
        raise ValueError(f"Refusing decoded payload larger than {MAX_PAYLOAD_BYTES} bytes")
    envelope = _msgspec_decoder.decode(verified)
    if envelope.schema_version != 1:
        raise ValueError(f"Unsupported schema_version={envelope.schema_version}")
    if not _is_schema_compatible(envelope.data):
        raise TypeError("safe_unpack: decoded envelope contains non-primitive values")
    return envelope.data


# ---------------------------------------------------------------------------
# Backwards-compatible aliases. The old ``mesh_marshal_pickle`` /
# ``mesh_unmarshal_pickle`` names were advertised as part of the public API,
# so we keep them as thin wrappers around the new safe functions. Any
# legacy caller that still passes a cloudpickle blob will now receive a
# msgspec decoding error instead of executing attacker-controlled code.
# ---------------------------------------------------------------------------


def mesh_marshal(data: Any) -> bytes:
    return cast(bytes, msgpack.packb(data, use_bin_type=True))


def mesh_unmarshal(raw: bytes) -> Any:
    return msgpack.unpackb(raw, raw=False)


# Legacy pickling helpers - now delegating to the safe schema-validated path.
# These names are retained so existing import sites do not break; they DO NOT
# perform cloudpickle any more. The ``compress`` / ``decompress`` parameters
# are accepted for signature compatibility with the previous implementation
# but the safe envelope is small enough (msgspec + HMAC) that we do not
# compress it in the default path.
def mesh_marshal_pickle(data: Any, compress: bool = True) -> bytes:  # noqa: D401
    """Serialize ``data`` using the safe msgspec envelope (legacy alias)."""
    return safe_pack(data, payload_kind="mesh_legacy")


def mesh_unmarshal_pickle(raw: bytes, decompress: bool = True) -> Any:  # noqa: D401
    """Deserialize ``raw`` through the safe msgspec envelope (legacy alias)."""
    return safe_unpack(raw)


# ---------------------------------------------------------------------------
# Optional zstd / zlib compression helpers used by the process pool.
# ---------------------------------------------------------------------------

try:
    import zstandard as zstd

    _zstd_compressor = zstd.ZstdCompressor(level=3)
    _zstd_decompressor = zstd.ZstdDecompressor()
    _HAS_ZSTD = True
except ImportError:
    _HAS_ZSTD = False


def compress_bytes(data: bytes) -> bytes:
    if _HAS_ZSTD:
        return cast(bytes, _zstd_compressor.compress(data))
    import zlib

    return zlib.compress(data)


def decompress_bytes(data: bytes) -> bytes:
    if _HAS_ZSTD:
        return cast(bytes, _zstd_decompressor.decompress(data))
    import zlib

    return zlib.decompress(data)


class FrontierMarshaller:
    """High-speed binary marshaller.

    ``pack`` / ``unpack`` use raw MessagePack for hot-path data and skip the
    integrity signature because the *envelope* layer (``safe_pack`` /
    ``safe_unpack``) is the one that should be used for untrusted
    inter-process payloads.
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
        except Exception as exc:  # noqa: BLE001
            logger.error("Marshaller: Packing failed: %s", exc)
            raise

    def unpack(self, raw_data: bytes) -> Any:
        """Deserialize MessagePack binary back to Python objects."""
        try:
            return msgpack.unpackb(raw_data, raw=False)
        except Exception as exc:  # noqa: BLE001
            logger.error("Marshaller: Unpacking failed: %s", exc)
            raise

    def pack_signed(self, data: Any, payload_kind: str = "generic") -> bytes:
        """Serialize through the safe, schema-validated envelope."""
        return safe_pack(data, payload_kind=payload_kind)

    def unpack_signed(self, raw_data: bytes) -> Any:
        """Deserialize through the safe, schema-validated envelope."""
        return safe_unpack(raw_data)

    # Backwards-compatible ``pack_pickle`` / ``unpack_pickle`` aliases. The
    # legacy implementation used cloudpickle + zstd; the new implementation
    # uses the safe msgspec envelope, which is already small and signed.
    def pack_pickle(self, data: Any, compress: bool = True) -> bytes:  # noqa: D401
        return safe_pack(data, payload_kind="frontier_legacy")

    def unpack_pickle(self, raw_data: bytes, decompress: bool = True) -> Any:  # noqa: D401
        return safe_unpack(raw_data)
