"""Unit tests for src.core.frontier.policies (PolicyEngine)."""

import unittest
from unittest.mock import MagicMock, patch

import pytest

from src.core.frontier.policies import PolicyEngine


class _StubVFS:
    def __init__(self) -> None:
        self._files: dict[str, bytes] = {}
        self._file_metadata: dict[str, dict] = {}
        self.deleted: list[str] = []

    def list_files(self) -> list[str]:
        return list(self._files.keys())

    def delete_file(self, path: str) -> None:
        self._files.pop(path, None)
        self._file_metadata.pop(path, None)
        self.deleted.append(path)

    def add(self, path: str, content: bytes, created_at: float) -> None:
        self._files[path] = content
        self._file_metadata[path] = {"created_at": created_at}


@pytest.mark.unit
class TestPolicyEngineDefaults(unittest.TestCase):
    def test_default_max_age_seconds(self) -> None:
        engine = PolicyEngine()
        self.assertEqual(engine.max_age_seconds, 86400.0)

    def test_default_max_file_count(self) -> None:
        engine = PolicyEngine()
        self.assertEqual(engine.max_file_count, 1000)

    def test_default_max_total_bytes(self) -> None:
        engine = PolicyEngine()
        self.assertEqual(engine.max_total_bytes, 50 * 1024 * 1024)

    def test_custom_values_preserved(self) -> None:
        engine = PolicyEngine(max_age_seconds=10.0, max_file_count=5, max_total_bytes=1024)
        self.assertEqual(engine.max_age_seconds, 10.0)
        self.assertEqual(engine.max_file_count, 5)
        self.assertEqual(engine.max_total_bytes, 1024)


@pytest.mark.unit
class TestPolicyEngineAgeRetention(unittest.TestCase):
    def test_removes_expired_files(self) -> None:
        vfs = _StubVFS()
        vfs.add("old.txt", b"x", created_at=100.0)
        vfs.add("new.txt", b"y", created_at=999.0)

        engine = PolicyEngine(max_age_seconds=1.0)
        with patch("src.core.frontier.policies.time.time", return_value=101.5):
            engine.enforce_retention(vfs)

        self.assertIn("old.txt", vfs.deleted)
        self.assertNotIn("new.txt", vfs.deleted)

    def test_keeps_fresh_files(self) -> None:
        vfs = _StubVFS()
        vfs.add("fresh.txt", b"x", created_at=100.0)

        engine = PolicyEngine(max_age_seconds=1000.0)
        with patch("src.core.frontier.policies.time.time", return_value=101.0):
            engine.enforce_retention(vfs)

        self.assertNotIn("fresh.txt", vfs.deleted)

    def test_continues_count_enforcement_after_age(self) -> None:
        vfs = _StubVFS()
        vfs.add("old1.txt", b"a", created_at=1.0)
        vfs.add("new1.txt", b"b", created_at=99.0)
        vfs.add("new2.txt", b"c", created_at=100.0)

        engine = PolicyEngine(max_age_seconds=5.0, max_file_count=1)
        with patch("src.core.frontier.policies.time.time", return_value=100.0):
            engine.enforce_retention(vfs)

        self.assertIn("old1.txt", vfs.deleted)
        self.assertEqual(len(vfs._files), 1)


@pytest.mark.unit
class TestPolicyEngineCountRetention(unittest.TestCase):
    def test_prunes_oldest_files_when_count_exceeded(self) -> None:
        vfs = _StubVFS()
        vfs.add("a.txt", b"a", created_at=10.0)
        vfs.add("b.txt", b"b", created_at=20.0)
        vfs.add("c.txt", b"c", created_at=30.0)
        vfs.add("d.txt", b"d", created_at=40.0)
        vfs.add("e.txt", b"e", created_at=50.0)

        engine = PolicyEngine(
            max_age_seconds=10_000.0,
            max_file_count=2,
            max_total_bytes=10_000_000,
        )
        with patch("src.core.frontier.policies.time.time", return_value=100.0):
            engine.enforce_retention(vfs)

        self.assertIn("a.txt", vfs.deleted)
        self.assertIn("b.txt", vfs.deleted)
        self.assertIn("c.txt", vfs.deleted)
        self.assertNotIn("d.txt", vfs.deleted)
        self.assertNotIn("e.txt", vfs.deleted)

    def test_does_nothing_under_limit(self) -> None:
        vfs = _StubVFS()
        vfs.add("a.txt", b"a", created_at=10.0)
        vfs.add("b.txt", b"b", created_at=20.0)

        engine = PolicyEngine(
            max_age_seconds=10_000.0,
            max_file_count=10,
            max_total_bytes=10_000_000,
        )
        with patch("src.core.frontier.policies.time.time", return_value=100.0):
            engine.enforce_retention(vfs)

        self.assertEqual(vfs.deleted, [])


@pytest.mark.unit
class TestPolicyEngineSizeRetention(unittest.TestCase):
    def test_prunes_oldest_files_when_size_exceeded(self) -> None:
        vfs = _StubVFS()
        vfs.add("a.txt", b"x" * 100, created_at=10.0)
        vfs.add("b.txt", b"y" * 100, created_at=20.0)
        vfs.add("c.txt", b"z" * 100, created_at=30.0)

        engine = PolicyEngine(
            max_age_seconds=10_000.0,
            max_file_count=1000,
            max_total_bytes=150,
        )
        with patch("src.core.frontier.policies.time.time", return_value=100.0):
            engine.enforce_retention(vfs)

        self.assertIn("a.txt", vfs.deleted)
        self.assertIn("b.txt", vfs.deleted)
        self.assertNotIn("c.txt", vfs.deleted)

    def test_under_size_limit_no_pruning(self) -> None:
        vfs = _StubVFS()
        vfs.add("a.txt", b"x" * 10, created_at=10.0)

        engine = PolicyEngine(
            max_age_seconds=10_000.0,
            max_file_count=1000,
            max_total_bytes=1000,
        )
        with patch("src.core.frontier.policies.time.time", return_value=100.0):
            engine.enforce_retention(vfs)

        self.assertEqual(vfs.deleted, [])


@pytest.mark.unit
class TestPolicyEngineResilience(unittest.TestCase):
    def test_continues_when_delete_file_raises(self) -> None:
        vfs = MagicMock()
        vfs.list_files.return_value = ["a.txt", "b.txt"]
        vfs._file_metadata = {"a.txt": {"created_at": 0.0}, "b.txt": {"created_at": 0.0}}
        vfs._files = {"a.txt": b"x", "b.txt": b"y"}
        vfs.delete_file.side_effect = [RuntimeError("boom"), None]

        engine = PolicyEngine(max_age_seconds=1.0, max_file_count=1, max_total_bytes=1_000_000)
        with patch("src.core.frontier.policies.time.time", return_value=10_000.0):
            engine.enforce_retention(vfs)

        self.assertGreaterEqual(vfs.delete_file.call_count, 1)

    def test_handles_missing_metadata_defaults_to_now(self) -> None:
        vfs = _StubVFS()
        vfs._file_metadata = {}
        vfs.add("a.txt", b"x", created_at=0.0)

        engine = PolicyEngine(max_age_seconds=10_000.0)
        with patch("src.core.frontier.policies.time.time", return_value=100.0):
            engine.enforce_retention(vfs)

        self.assertNotIn("a.txt", vfs.deleted)


if __name__ == "__main__":
    unittest.main()
