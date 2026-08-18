"""Coverage for previously untested S3 backend path helpers."""

from __future__ import annotations

import pytest

from src.core.storage.s3_backends import _parse_version_id, _stage_safe_name, _stream_s3_body


class _ChunkedBody:
    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = list(chunks)

    def read(self, _size: int) -> bytes:
        return self._chunks.pop(0) if self._chunks else b""


@pytest.mark.unit
@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("v0", 0),
        ("v1", 1),
        ("v12", 12),
        ("v000007", 7),
    ],
)
def test_parse_version_id_valid(value: str, expected: int) -> None:
    assert _parse_version_id(value) == expected


@pytest.mark.unit
@pytest.mark.parametrize("value", ["", "1", "vx", "v", "version-1", 3])
def test_parse_version_id_invalid(value: object) -> None:
    with pytest.raises(ValueError, match="Invalid checkpoint version id"):
        _parse_version_id(value)  # type: ignore[arg-type]


@pytest.mark.unit
def test_stage_safe_name_strips_and_rejects_path_chars() -> None:
    assert _stage_safe_name("  recon  ") == "recon"
    assert _stage_safe_name("") == "unknown"
    assert _stage_safe_name("   ") == "unknown"
    with pytest.raises(ValueError, match="Invalid stage name"):
        _stage_safe_name("../etc")
    with pytest.raises(ValueError, match="Invalid stage name"):
        _stage_safe_name("a/b")
    with pytest.raises(ValueError, match="Invalid stage name"):
        _stage_safe_name("a\\b")


@pytest.mark.unit
def test_stream_s3_body_joins_chunks() -> None:
    assert _stream_s3_body(_ChunkedBody([b"hello", b"", b"ignored"])) == b"hello"
    assert _stream_s3_body(_ChunkedBody([b"ab", b"cd", b"ef", b""])) == b"abcdef"
    assert _stream_s3_body(_ChunkedBody([b""])) == b""
