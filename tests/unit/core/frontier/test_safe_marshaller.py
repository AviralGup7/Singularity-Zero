"""Tests for the safe msgspec-based frontier marshaller (replaces cloudpickle)."""

import importlib
import os
from typing import Any

import pytest

from src.core.frontier import marshaller
from src.core.frontier.marshaller import (
    MAX_PAYLOAD_BYTES,
    safe_pack,
    safe_unpack,
)


def _new_marshaller():
    """Build a marshaller instance (no per-instance secret in the safe path)."""
    return marshaller.FrontierMarshaller()


def test_safe_pack_returns_bytes_with_envelope():
    packed = safe_pack({"a": 1, "b": [1, 2, 3]}, payload_kind="test_kind")
    assert isinstance(packed, bytes)
    assert len(packed) > 0


def test_safe_unpack_roundtrip_preserves_dict():
    data = {"findings": [{"id": 1, "sev": "high"}], "status": "active"}
    packed = safe_pack(data, payload_kind="roundtrip")
    unpacked = safe_unpack(packed)
    assert unpacked == data


def test_safe_unpack_roundtrip_preserves_list_and_scalars():
    data = [1, "two", 3.0, True, None, {"nested": [4, 5]}]
    packed = safe_pack(data, payload_kind="scalars")
    assert safe_unpack(packed) == data


def test_safe_pack_rejects_callable():
    with pytest.raises((TypeError, Exception)):
        safe_pack(lambda x: x, payload_kind="bad")


def test_safe_pack_rejects_generator():
    with pytest.raises((TypeError, Exception)):
        safe_pack((i for i in range(5)), payload_kind="bad")


def test_safe_unpack_rejects_oversized_payload():
    huge = b"x" * (MAX_PAYLOAD_BYTES + 1)
    with pytest.raises((ValueError, Exception)):
        safe_unpack(huge)


def test_safe_unpack_rejects_truncated_bytes():
    with pytest.raises((ValueError, Exception)):
        safe_unpack(b"\x01\x02\x03\x04")


def test_safe_unpack_rejects_tampered_hmac(monkeypatch):
    packed = safe_pack({"ok": True}, payload_kind="integrity")
    # Flip a bit in the middle of the bytes to break the HMAC
    tampered = bytearray(packed)
    tampered[-5] ^= 0xFF
    with pytest.raises((ValueError, Exception)):
        safe_unpack(bytes(tampered))


def test_safe_unpack_rejects_wrong_secret(monkeypatch):
    packed = safe_pack({"ok": True}, payload_kind="secrecy")
    # Override the default secret so HMAC verification fails
    monkeypatch.setattr(marshaller, "_MESH_SECRET", b"other-secret-bytes-32-aaaaaaaaaa")
    with pytest.raises((ValueError, Exception)):
        marshaller.safe_unpack(packed)


def test_safe_pack_with_custom_payload_kind_roundtrip():
    data = {"k": "v"}
    packed = safe_pack(data, payload_kind="custom-pipeline")
    assert safe_unpack(packed) == data


def test_frontier_marshaller_class_roundtrip():
    m = _new_marshaller()
    packed = m.pack_signed({"x": 1}, payload_kind="class-test")
    assert m.unpack_signed(packed) == {"x": 1}


def test_legacy_pack_pickle_alias_roundtrip():
    m = _new_marshaller()
    data = {"legacy": True, "items": [1, 2, 3]}
    packed = m.pack_pickle(data, compress=True)
    assert m.unpack_pickle(packed, decompress=True) == data


def test_legacy_mesh_helpers_roundtrip():
    data = [1, "two", {"three": 3}]
    packed = marshaller.mesh_marshal_pickle(data, compress=False)
    assert marshaller.mesh_unmarshal_pickle(packed, decompress=False) == data


def test_no_pickle_in_marshaller_source():
    """Regression: the actual pickle.loads / cloudpickle import paths
    must not re-appear in the marshaller module."""
    import re
    src = open(marshaller.__file__, encoding="utf-8").read()
    # Strip docstrings/comments so we only scan executable code
    code_lines = []
    for line in src.splitlines():
        s = line.strip()
        if s.startswith("#") or s.startswith('"""') or s.startswith("'''"):
            continue
        code_lines.append(line)
    code = "\n".join(code_lines)
    assert "import cloudpickle" not in code
    assert "from cloudpickle" not in code
    assert "pickle.loads" not in code
    assert "pickle.load(" not in code


def test_envelope_includes_schema_fields():
    """The envelope must contain schema_version + payload_kind."""
    from src.core.frontier.marshaller import _MarshalledEnvelope, safe_pack, _verify_payload
    packed = safe_pack({"x": 1}, payload_kind="schema-fields")
    # Strip the HMAC signature to access the inner envelope
    inner = _verify_payload(packed)
    decoded = marshaller._msgspec_decoder.decode(inner)
    assert decoded.schema_version >= 1
    assert decoded.payload_kind == "schema-fields"
    assert decoded.data == {"x": 1}


@pytest.mark.parametrize(
    "data",
    [
        {"a": 1},
        [1, 2, 3],
        "string-value",
        42,
        3.14,
        True,
        None,
        {"nested": {"deep": {"deeper": [1, 2, 3]}}},
    ],
)
def test_safe_pack_parametrized_types(data: Any):
    packed = safe_pack(data, payload_kind="param")
    assert safe_unpack(packed) == data


def test_dev_secret_loads_from_env(monkeypatch):
    """When the operator doesn't set MESH_SECRET, the dev fallback is random
    but stable for the lifetime of the process."""
    monkeypatch.delenv("MESH_SECRET", raising=False)
    importlib.reload(marshaller)
    s1 = marshaller._MESH_SECRET
    s2 = marshaller._MESH_SECRET
    assert s1 == s2  # stable within process
    assert len(s1) >= 16


def test_production_requires_mesh_secret_env(monkeypatch):
    """In production we must NOT fall back to a random secret."""
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.delenv("MESH_SECRET", raising=False)
    with pytest.raises((RuntimeError, ValueError, Exception)):
        importlib.reload(marshaller)
        # The reload would have raised during module-level validation
    monkeypatch.delenv("APP_ENV", raising=False)
    importlib.reload(marshaller)
