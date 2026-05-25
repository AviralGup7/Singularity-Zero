import pytest

from src.core.frontier.marshaller import (
    FrontierMarshaller,
    compress_bytes,
    decompress_bytes,
    mesh_marshal,
    mesh_marshal_pickle,
    mesh_unmarshal,
    mesh_unmarshal_pickle,
)


def test_marshaller_roundtrip():
    data = {"findings": [{"id": 1, "severity": "HIGH"}], "status": "active"}

    marshaller = FrontierMarshaller()
    packed = marshaller.pack(data)
    assert isinstance(packed, bytes)

    unpacked = marshaller.unpack(packed)
    assert unpacked == data


def test_mesh_helpers_roundtrip():
    data = [1, 2, "three", {"four": 5}]
    packed = mesh_marshal(data)
    assert isinstance(packed, bytes)

    unpacked = mesh_unmarshal(packed)
    assert unpacked == data


def test_compress_decompress_bytes():
    payload = b"test payload for zstd compression"
    compressed = compress_bytes(payload)
    assert isinstance(compressed, bytes)
    decompressed = decompress_bytes(compressed)
    assert decompressed == payload


def test_zlib_compression_fallback(monkeypatch):
    # Temporarily force zlib compression instead of mutating sys.modules
    import src.core.frontier.marshaller as marshaller_mod

    monkeypatch.setattr(marshaller_mod, "_FORCE_ZLIB", True)

    payload = b"test payload for fallback compression"
    compressed = marshaller_mod.compress_bytes(payload)
    assert isinstance(compressed, bytes)
    decompressed = marshaller_mod.decompress_bytes(compressed)
    assert decompressed == payload


def test_pack_unpack_errors():
    marshaller = FrontierMarshaller()

    # msgpack cannot serialize lambda/function objects
    with pytest.raises(Exception):
        marshaller.pack(lambda: None)

    # msgpack cannot unpack invalid msgpack bytes
    with pytest.raises(Exception):
        marshaller.unpack(b"\xc1")


def test_pickle_roundtrip():
    marshaller = FrontierMarshaller()
    data = {"nested": [1, 2, 3], "type": "crdt"}

    # Test with compression
    packed_compressed = marshaller.pack_pickle(data, compress=True)
    assert isinstance(packed_compressed, bytes)
    unpacked_compressed = marshaller.unpack_pickle(packed_compressed, decompress=True)
    assert unpacked_compressed == data

    # Test without compression
    packed_uncompressed = marshaller.pack_pickle(data, compress=False)
    assert isinstance(packed_uncompressed, bytes)
    unpacked_uncompressed = marshaller.unpack_pickle(packed_uncompressed, decompress=False)
    assert unpacked_uncompressed == data


def test_pickle_errors():
    marshaller = FrontierMarshaller()

    # Generator expressions cannot be pickled (even by cloudpickle) and should raise an exception
    with pytest.raises(Exception):
        marshaller.pack_pickle(x for x in range(10))

    # Invalid bytes cannot be unpickled
    with pytest.raises(Exception):
        marshaller.unpack_pickle(b"invalid corrupt pickle bytes")


def test_mesh_pickle_helpers_roundtrip():
    data = {"mesh_node_id": "node_99", "state": "active"}

    # Test with compression
    packed_comp = mesh_marshal_pickle(data, compress=True)
    assert isinstance(packed_comp, bytes)
    unpacked_comp = mesh_unmarshal_pickle(packed_comp, decompress=True)
    assert unpacked_comp == data

    # Test without compression
    packed_uncomp = mesh_marshal_pickle(data, compress=False)
    assert isinstance(packed_uncomp, bytes)
    unpacked_uncomp = mesh_unmarshal_pickle(packed_uncomp, decompress=False)
    assert unpacked_uncomp == data
