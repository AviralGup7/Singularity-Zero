"""Protobuf payload generators for fuzzing."""


def invalid_varint() -> bytes:
    """Return a byte sequence where the high bit is always set (invalid varint)."""
    return bytes([0xFF] * 10)


def wrong_wire_type(field_tag: int, expected_wire: int, wrong_wire: int) -> bytes:
    """Encode *field_tag* with *wrong_wire* instead of *expected_wire*."""
    if wrong_wire == 0:
        return _encode_varint((field_tag << 3) | wrong_wire)
    if wrong_wire == 1:
        return _encode_varint(field_tag << 3 | 1) + b"\x00" * 8
    if wrong_wire == 2:
        return _encode_varint(field_tag << 3 | 2) + b"\x00\x00"
    if wrong_wire == 5:
        return _encode_varint(field_tag << 3 | 5) + b"\x00\x00\x00\x00"
    return _encode_varint(field_tag << 3 | wrong_wire)


def recursive_depth_bomb(depth: int = 101) -> bytes:
    """Return a length-delimited payload repeated *depth* times to trigger recursion limits."""
    inner = b"\x00"
    payload = inner
    for _ in range(depth):
        payload = _encode_length_delimited(payload)
    return payload


def missing_required_field(descriptor: bytes) -> bytes:
    """Return *descriptor* with all field payloads stripped (all required fields missing)."""
    return b""


def _encode_varint(value: int) -> bytes:
    """Encode *value* as a protobuf varint."""
    result = bytearray()
    while value > 0x7F:
        result.append((value & 0x7F) | 0x80)
        value >>= 7
    result.append(value & 0x7F)
    return bytes(result)


def _encode_length_delimited(data: bytes) -> bytes:
    """Encode *data* as a protobuf length-delimited field (wire type 2)."""
    return _encode_varint(len(data)) + data
