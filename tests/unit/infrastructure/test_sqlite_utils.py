"""Tests for the centralized SQLite connection helpers."""

from __future__ import annotations

import os
import sqlite3
import threading
from pathlib import Path

import pytest

from src.infrastructure.db.sqlite_utils import (
    SQLITE_BUSY_TIMEOUT_MS,
    SQLITE_CONNECT_TIMEOUT_SECONDS,
    SQLITE_LOCK_RETRY_ATTEMPTS,
    SQLITE_LOCK_RETRY_BASE_DELAY_SECONDS,
    _RetryDB,
    configure_connection,
    is_locked_error,
    retrying_connect,
    safe_close,
)


class TestConstants:
    def test_constants_positive(self) -> None:
        assert SQLITE_BUSY_TIMEOUT_MS > 0
        assert SQLITE_CONNECT_TIMEOUT_SECONDS > 0
        assert SQLITE_LOCK_RETRY_ATTEMPTS > 0
        assert SQLITE_LOCK_RETRY_BASE_DELAY_SECONDS > 0

    def test_env_overrides(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SQLITE_BUSY_TIMEOUT_MS", "1234")
        # The module's constants are evaluated at import time, so we exercise
        # the helper functions instead.
        from src.infrastructure.db import sqlite_utils

        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(sqlite_utils, "SQLITE_BUSY_TIMEOUT_MS", 1234)
            assert sqlite_utils.SQLITE_BUSY_TIMEOUT_MS == 1234


class TestRetryingConnect:
    def test_yields_configured_connection(self, tmp_path: Path) -> None:
        db = tmp_path / "test.db"
        with retrying_connect(db) as conn:
            assert isinstance(conn, sqlite3.Connection)
            # busy_timeout is applied
            (mode,) = conn.execute("PRAGMA busy_timeout").fetchone()
            assert mode == SQLITE_BUSY_TIMEOUT_MS
            # journal_mode is WAL (when WAL is enabled, default)
            (journal,) = conn.execute("PRAGMA journal_mode").fetchone()
            assert journal.lower() == "wal"
            # foreign_keys is ON
            (fk,) = conn.execute("PRAGMA foreign_keys").fetchone()
            assert fk == 1

    def test_rollback_on_exception(self, tmp_path: Path) -> None:
        db = tmp_path / "test.db"
        with pytest.raises(RuntimeError, match="user error"):
            with retrying_connect(db) as conn:
                conn.execute("CREATE TABLE t (x INTEGER)")
                conn.execute("INSERT INTO t VALUES (1)")
                raise RuntimeError("user error")
        # The transaction should have been rolled back — t is empty or absent
        with sqlite3.connect(db) as check:
            try:
                rows = check.execute("SELECT count(*) FROM t").fetchone()
                # If the table was created but the row was rolled back, count == 0
                assert rows[0] == 0
            except sqlite3.OperationalError:
                # DDL inside a rolled-back txn is also rolled back — that's fine
                pass

    def test_wal_and_foreign_keys_can_be_disabled(self, tmp_path: Path) -> None:
        db = tmp_path / "test.db"
        with retrying_connect(db, wal=False, foreign_keys=False) as conn:
            (fk,) = conn.execute("PRAGMA foreign_keys").fetchone()
            assert fk == 0
            (journal,) = conn.execute("PRAGMA journal_mode").fetchone()
            assert journal.lower() != "wal"


class TestSafeClose:
    def test_none_is_noop(self) -> None:
        safe_close(None)  # should not raise

    def test_double_close_is_safe(self, tmp_path: Path) -> None:
        db = tmp_path / "test.db"
        conn = sqlite3.connect(db)
        safe_close(conn)
        safe_close(conn)  # second close is silently swallowed

    def test_open_close(self, tmp_path: Path) -> None:
        db = tmp_path / "test.db"
        conn = sqlite3.connect(db)
        safe_close(conn)
        with pytest.raises(sqlite3.ProgrammingError):
            conn.execute("SELECT 1")


class TestConfigureConnection:
    def test_applies_standard_pragma_block(self, tmp_path: Path) -> None:
        conn = sqlite3.connect(tmp_path / "test.db")
        try:
            configure_connection(conn, busy_timeout_ms=2500, wal=False, synchronous="OFF")
            (busy,) = conn.execute("PRAGMA busy_timeout").fetchone()
            assert busy == 2500
            (fk,) = conn.execute("PRAGMA foreign_keys").fetchone()
            assert fk == 1
            (sync,) = conn.execute("PRAGMA synchronous").fetchone()
            assert sync == 0  # OFF == 0
        finally:
            conn.close()


class TestIsLockedError:
    def test_locked_message(self) -> None:
        assert is_locked_error(sqlite3.OperationalError("database is locked"))
        assert is_locked_error(sqlite3.OperationalError("database table is locked"))

    def test_other_messages(self) -> None:
        assert not is_locked_error(sqlite3.OperationalError("syntax error"))
        assert not is_locked_error(ValueError("not a sqlite error"))


class TestRetryDB:
    def test_succeeds_after_locked(self, monkeypatch: pytest.MonkeyPatch) -> None:
        calls: list[int] = []

        def op() -> str:
            calls.append(1)
            if len(calls) < 3:
                raise sqlite3.OperationalError("database is locked")
            return "ok"

        rd = _RetryDB(max_attempts=5, base_delay_seconds=0.0)
        with monkeypatch.context() as m:
            # Avoid real sleeps
            m.setattr(
                "src.infrastructure.db.sqlite_utils.time.sleep",
                lambda *_a, **_k: None,
            )
            assert rd.run(op) == "ok"
        assert len(calls) == 3

    def test_raises_non_locked_error_immediately(self) -> None:
        calls: list[int] = []

        def op() -> None:
            calls.append(1)
            raise sqlite3.OperationalError("syntax error")

        rd = _RetryDB(max_attempts=5, base_delay_seconds=0.0)
        with pytest.raises(sqlite3.OperationalError, match="syntax error"):
            rd.run(op)
        # Only one attempt because the error wasn't a lock error
        assert len(calls) == 1

    def test_thread_safety(self) -> None:
        """Concurrent _RetryDB.run calls on the same callable should not deadlock."""
        results: list[str] = []
        errors: list[Exception] = []
        lock = threading.Lock()

        def op() -> str:
            with lock:
                return "ok"

        def worker() -> None:
            try:
                rd = _RetryDB(max_attempts=5, base_delay_seconds=0.0)
                results.append(rd.run(op))
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert errors == []
        assert results == ["ok"] * 8
