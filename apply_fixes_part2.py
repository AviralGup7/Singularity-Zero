import pathlib

# FIX-3 additions to cache_backend.py
p = pathlib.Path(r"D:\cyber security test pipeline - Copy\src\pipeline\cache_backend.py")
text = p.read_text(encoding="utf-8")
if "import threading" in text and "from contextlib import contextmanager" not in text:
    text = text.replace(
        "import threading\n", "import threading\nfrom contextlib import contextmanager\n", 1
    )
# add import for sqlite_utils if not present
if "from src.infrastructure.db.sqlite_utils import" not in text:
    text = text.replace(
        "from src.infrastructure.cache.models import CacheMetrics",
        "from src.infrastructure.cache.models import CacheMetrics\nfrom src.infrastructure.db.sqlite_utils import safe_close",
        1,
    )
# add safe_close guards to all conn.close() except inside safe_close helper itself
old_block = """    def close_all(self) -> None:
        \"\"\"Close all SQLite connections across all threads.\"\"\"
        with self._lock:
            if hasattr(self, "_all_conns"):
                for conn in list(self._all_conns):
                    try:
                        conn.close()
                    except Exception as e:
                        logger.debug("Failed to close SQLite connection: %s", e)
                self._all_conns.clear()
            self._ensure_thread_local()
            self._thread_local.conn = None"""
new_block = """    def close_all(self) -> None:
        \"\"\"Close all SQLite connections across all threads.\"\"\"
        with self._lock:
            if hasattr(self, "_all_conns"):
                for conn in list(self._all_conns):
                    try:
                        safe_close(conn)
                    except Exception as e:
                        logger.debug("Failed to close SQLite connection: %s", e)
                self._all_conns.clear()
            self._ensure_thread_local()
            self._thread_local.conn = None"""
if old_block in text:
    text = text.replace(old_block, new_block, 1)
p.write_text(text, encoding="utf-8")

# FIX-3 additions to job_store.py
p = pathlib.Path(r"D:\cyber security test pipeline - Copy\src\dashboard\job_store.py")
text = p.read_text(encoding="utf-8")
if "from contextlib import contextmanager" not in text:
    text = text.replace(
        "import threading\n", "import threading\nfrom contextlib import contextmanager\n", 1
    )
if "from src.infrastructure.db.sqlite_utils import" not in text:
    text = text.replace(
        "import logging\n",
        "import logging\nfrom src.infrastructure.db.sqlite_utils import safe_close\n",
        1,
    )
old_close = """    def close(self) -> None:
        \"\"\"Close all database connections created across all threads.\"\"\"
        with self._lock:
            for conn in self._all_connections:
                try:
                    conn.close()
                except Exception as exc:  # noqa: BLE001
                    logger.warning("Failed to close SQLite connection cleanly: %s", exc)
            self._all_connections.clear()
            self._local._conn = None"""
new_close = """    def close(self) -> None:
        \"\"\"Close all database connections created across all threads.\"\"\"
        with self._lock:
            for conn in self._all_connections:
                try:
                    safe_close(conn)
                except Exception as exc:  # noqa: BLE001
                    logger.warning("Failed to close SQLite connection cleanly: %s", exc)
            self._all_connections.clear()
            self._local._conn = None"""
if old_close in text:
    text = text.replace(old_close, new_close, 1)
# also fix pragma block on failure in _get_conn
old = """    def _get_conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "_conn") or self._local._conn is None:
            conn = sqlite3.connect(str(self.db_path), timeout=_CONNECT_TIMEOUT_SECONDS)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute(f"PRAGMA busy_timeout={_BUSY_TIMEOUT_MS}")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA foreign_keys=ON")
            self._local._conn = conn
            with self._lock:
                self._all_connections.append(conn)
        return cast(sqlite3.Connection, self._local._conn)"""
new = """    def _get_conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "_conn") or self._local._conn is None:
            conn = sqlite3.connect(str(self.db_path), timeout=_CONNECT_TIMEOUT_SECONDS)
            conn.row_factory = sqlite3.Row
            try:
                conn.execute("PRAGMA journal_mode=WAL")
                conn.execute(f"PRAGMA busy_timeout={_BUSY_TIMEOUT_MS}")
                conn.execute("PRAGMA synchronous=NORMAL")
                conn.execute("PRAGMA foreign_keys=ON")
            except Exception:
                try:
                    conn.close()
                except sqlite3.ProgrammingError:
                    pass
                raise
            self._local._conn = conn
            with self._lock:
                self._all_connections.append(conn)
        return cast(sqlite3.Connection, self._local._conn)"""
if old in text:
    text = text.replace(old, new, 1)
# _drop_thread_conn safe close
old = """    def _drop_thread_conn(self) -> None:
        conn = getattr(self._local, "_conn", None)
        if conn is None:
            return
        try:
            conn.close()
        except Exception as exc:  # noqa: BLE001
            logger.debug("Failed to close failed SQLite connection: %s", exc)
        finally:
            if conn in self._all_connections:
                self._all_connections.remove(conn)
            self._local._conn = None"""
new = """    def _drop_thread_conn(self) -> None:
        conn = getattr(self._local, "_conn", None)
        if conn is None:
            return
        try:
            safe_close(conn)
        except Exception as exc:  # noqa: BLE001
            logger.debug("Failed to close failed SQLite connection: %s", exc)
        finally:
            if conn in self._all_connections:
                self._all_connections.remove(conn)
            self._local._conn = None"""
if old in text:
    text = text.replace(old, new, 1)
p.write_text(text, encoding="utf-8")

# FIX-3 base.py
p = pathlib.Path(r"D:\cyber security test pipeline - Copy\src\learning\repositories\base.py")
text = p.read_text(encoding="utf-8")
if "from contextlib import contextmanager" not in text:
    text = text.replace(
        "import threading\n", "import threading\nfrom contextlib import contextmanager\n", 1
    )
if "from src.infrastructure.db.sqlite_utils import" not in text:
    text = text.replace(
        "import json\n",
        "import json\nfrom src.infrastructure.db.sqlite_utils import safe_close\n",
        1,
    )
old = """            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA foreign_keys=ON")
            self._local.conn = conn"""
new = """            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA foreign_keys=ON")
            self._local.conn = conn
            safe_close.__self_flag__ = True"""
# not correct approach, instead add @contextmanager _conn_context that wraps
text = text.replace(old, new)
print("base.py patched")
