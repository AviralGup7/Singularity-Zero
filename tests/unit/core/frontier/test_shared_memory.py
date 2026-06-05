"""Unit tests for src.core.frontier.shared_memory (SharedMemoryBuffer + ZeroCopyRouter)."""

import unittest
import uuid

import pytest

from src.core.frontier.shared_memory import (
    _HEADER_MAGIC,
    _HEADER_SIZE,
    _HEADER_VERSION,
    _MAX_PAYLOAD_BYTES,
    SharedMemoryBuffer,
    ZeroCopyRouter,
)


def _unique_name(prefix: str = "test_shm") -> str:
    return f"{prefix}_{uuid.uuid4().hex[:8]}"


@pytest.mark.unit
class TestSharedMemoryBuffer(unittest.TestCase):
    def setUp(self) -> None:
        self.name = _unique_name()
        self.size = 4096
        self.buf = SharedMemoryBuffer(self.name, self.size, create=True)

    def tearDown(self) -> None:
        try:
            self.buf.close()
        except Exception:
            pass

    def test_write_and_read_roundtrip(self) -> None:
        data = b"hello shared memory"
        self.buf.write(data, offset=0)
        self.assertEqual(self.buf.read(len(data), offset=0), data)

    def test_write_at_offset(self) -> None:
        first = b"AAAA"
        second = b"BBBB"
        self.buf.write(first, offset=0)
        self.buf.write(second, offset=4)
        self.assertEqual(self.buf.read(4, offset=0), first)
        self.assertEqual(self.buf.read(4, offset=4), second)

    def test_write_returns_bytes_written(self) -> None:
        self.assertEqual(self.buf.write(b"abc", offset=0), 3)

    def test_write_exceeds_buffer_raises(self) -> None:
        with self.assertRaises(ValueError):
            self.buf.write(b"x" * (self.size + 1), offset=0)

    def test_write_overflows_at_offset_raises(self) -> None:
        with self.assertRaises(ValueError):
            self.buf.write(b"x" * 100, offset=self.size - 50)

    def test_read_exceeds_buffer_raises(self) -> None:
        with self.assertRaises(ValueError):
            self.buf.read(self.size + 1, offset=0)

    def test_read_at_invalid_offset_raises(self) -> None:
        with self.assertRaises(ValueError):
            self.buf.read(10, offset=-1)

    def test_close_releases_segment(self) -> None:
        self.buf.close()
        try:
            self.buf.close()
        except Exception:
            pass

    def test_name_and_size_attributes(self) -> None:
        self.assertEqual(self.buf.name, self.name)
        self.assertEqual(self.buf.size, self.size)


@pytest.mark.unit
class TestZeroCopyRouter(unittest.TestCase):
    def setUp(self) -> None:
        self.name = _unique_name("test_zcr")
        self.router = ZeroCopyRouter(buffer_name=self.name, buffer_size=64 * 1024)
        self.created: list[ZeroCopyRouter] = []

    def tearDown(self) -> None:
        try:
            self.router.close()
        finally:
            for r in self.created:
                try:
                    r.close()
                except Exception:
                    pass

    def test_route_payload_returns_location_string(self) -> None:
        loc = self.router.route_payload(b"hello")
        self.assertTrue(loc.startswith("shm://"))
        self.assertIn(self.name, loc)

    def test_retrieve_payload_roundtrip(self) -> None:
        payload = b"the quick brown fox jumps over the lazy dog"
        loc = self.router.route_payload(payload)
        self.assertEqual(self.router.retrieve_payload(loc), payload)

    def test_invalid_payload_type_raises(self) -> None:
        with self.assertRaises(TypeError):
            self.router.route_payload("not bytes")

    def test_oversized_payload_raises(self) -> None:
        with self.assertRaises(ValueError):
            self.router.route_payload(b"x" * (_MAX_PAYLOAD_BYTES + 1))

    def test_payload_larger_than_buffer_raises(self) -> None:
        tiny = ZeroCopyRouter(buffer_name=_unique_name("tiny"), buffer_size=10)
        with self.assertRaises(ValueError):
            tiny.route_payload(b"x" * 1000)
        tiny.close()

    def test_retrieve_invalid_protocol_raises(self) -> None:
        with self.assertRaises(ValueError):
            self.router.retrieve_payload("http://not-shm/loc")

    def test_retrieve_malformed_location_raises(self) -> None:
        with self.assertRaises(ValueError):
            self.router.retrieve_payload("shm://missing-at-sign")

    def test_retrieve_corrupted_magic_raises(self) -> None:
        corrupt_name = _unique_name("test_zcr_corrupt")
        corrupt_router = ZeroCopyRouter(buffer_name=corrupt_name, buffer_size=64 * 1024)
        try:
            corrupt_router.route_payload(b"x")
            shm = corrupt_router._shm
            shm.write(b"XXXX" + b"\x00" * (_HEADER_SIZE - 4), offset=0)
            with self.assertRaises(ValueError):
                corrupt_router.retrieve_payload(f"shm://{corrupt_name}@0:1")
        finally:
            corrupt_router.close()

    def test_retrieve_offset_out_of_bounds_raises(self) -> None:
        with self.assertRaises(ValueError):
            self.router.retrieve_payload(f"shm://{self.name}@-1:0")

    def test_retrieve_declared_length_too_large_raises(self) -> None:
        with self.assertRaises(ValueError):
            self.router.retrieve_payload(f"shm://{self.name}@0:{_MAX_PAYLOAD_BYTES + 1}")

    def test_retrieve_declared_payload_overflow_raises(self) -> None:
        with self.assertRaises(ValueError):
            self.router.retrieve_payload(f"shm://{self.name}@{self.router.buffer_size - 2}:10")

    def test_buffer_size_clamped_to_header_minimum(self) -> None:
        r = ZeroCopyRouter(buffer_name=_unique_name("min"), buffer_size=2)
        self.assertGreaterEqual(r.buffer_size, _HEADER_SIZE + 16)
        r.close()

    def test_header_constants_consistent(self) -> None:
        self.assertEqual(_HEADER_MAGIC, b"FPSH")
        self.assertEqual(_HEADER_VERSION, 1)
        self.assertEqual(_HEADER_SIZE, 12)
        self.assertGreater(_MAX_PAYLOAD_BYTES, 0)


if __name__ == "__main__":
    unittest.main()
