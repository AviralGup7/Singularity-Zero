import pathlib

# ========================= job_store.py =========================
p = pathlib.Path(r"D:\cyber security test pipeline - Copy\src\dashboard\job_store.py")
text = p.read_text(encoding="utf-8")
text = text.replace(
    "import logging\nfrom src.infrastructure.db.sqlite_utils import safe_close\nimport sqlite3\n",
    "import json\nimport logging\nimport sqlite3\n",
)
text = text.replace(
    "from src.infrastructure.db.sqlite_utils import safe_close\nimport sqlite3\n",
    "import sqlite3\n",
)
text = text.replace(
    "import sqlite3\nimport threading\n",
    "import sqlite3\nimport threading\nfrom src.infrastructure.db.sqlite_utils import safe_close\n",
)
text = text.replace(
    '''    def close(self) -> None:
        """Close all database connections created across all threads."""
        with self._lock:
            for conn in self._all_connections:
                try:
                    conn.close()
                except Exception as exc:  # noqa: BLE001
                    logger.warning("Failed to close SQLite connection cleanly: %s", exc)
            self._all_connections.clear()
            self._local._conn = None''',
    "",
)
p.write_text(text, encoding="utf-8")

# ========================= base.py =========================
p = pathlib.Path(r"D:\cyber security test pipeline - Copy\src\learning\repositories\base.py")
text = p.read_text(encoding="utf-8")
if "from src.infrastructure.db.sqlite_utils import" not in text:
    text = text.replace(
        "import threading\n",
        "import threading\nfrom src.infrastructure.db.sqlite_utils import safe_close\n",
    )
old = '''    def _get_conn(self) -> sqlite3.Connection:
        """Get a thread-local database connection."""
        if not hasattr(self._local, "conn") or self._local.conn is None:
            conn = sqlite3.connect(
                str(self.db_path),
                check_same_thread=False,
            )
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA foreign_keys=ON")
            self._local.conn = conn
            with BaseRepo._lock:
                # Clean up any closed connections to prevent accumulation
                to_remove = set()
                for c in BaseRepo._connections:
                    try:
                        # Try to execute a simple PRAGMA to see if it is closed
                        c.execute("SELECT 1")
                    except sqlite3.ProgrammingError:
                        to_remove.add(c)
                BaseRepo._connections.difference_update(to_remove)
                BaseRepo._connections.add(conn)
        return cast(sqlite3.Connection, self._local.conn)'''
new = '''    def _get_conn(self) -> sqlite3.Connection:
        """Get a thread-local database connection."""
        if not hasattr(self._local, "conn") or self._local.conn is None:
            conn = sqlite3.connect(
                str(self.db_path),
                check_same_thread=False,
            )
            conn.row_factory = sqlite3.Row
            try:
                conn.execute("PRAGMA journal_mode=WAL")
                conn.execute("PRAGMA foreign_keys=ON")
            except Exception:
                try:
                    conn.close()
                except sqlite3.ProgrammingError:
                    pass
                raise
            self._local.conn = conn
            with BaseRepo._lock:
                # Clean up any closed connections to prevent accumulation
                to_remove = set()
                for c in BaseRepo._connections:
                    try:
                        # Try to execute a simple PRAGMA to see if it is closed
                        c.execute("SELECT 1")
                    except sqlite3.ProgrammingError:
                        to_remove.add(c)
                BaseRepo._connections.difference_update(to_remove)
                BaseRepo._connections.add(conn)
        return cast(sqlite3.Connection, self._local.conn)'''
if old in text:
    text = text.replace(old, new)
p.write_text(text, encoding="utf-8")

# ========================= ghost_vfs.py =========================
p = pathlib.Path(r"D:\cyber security test pipeline - Copy\src\core\frontier\ghost_vfs.py")
text = p.read_text(encoding="utf-8")
old = """    @staticmethod
    def pin_memory(address_space: Any) -> None:
        \"\"\"Lock memory using eBPF to prevent swapping and dumping (Unsupported).\"\"\"
        pass

    @staticmethod
    def unpin_memory(address_space: Any) -> None:
        pass"""
new = """    @staticmethod
    def pin_memory(address_space: Any) -> None:
        \"\"\"Lock memory using eBPF to prevent swapping and dumping (Unsupported).\"\"\"
        pass

    @staticmethod
    def unpin_memory(address_space: Any) -> None:
        pass

# NOTE: FIX-6 sed-style replacements applied via regex below due to multi-occurrence"""
text = text.replace(old, new)
# replace bare except pass with logger warnings
text = text.replace(
    "        pass\n\n\nclass VFSEncryptionPolicy:", "        pass\n\n\nclass VFSEncryptionPolicy:"
)
# Global sed-style: except Exception: pass  -> logger.warning
lines = text.splitlines(keepends=True)
result = []
i = 0
while i < len(lines):
    line = lines[i]
    if (
        line.strip() == "except Exception:"
        and i + 1 < len(lines)
        and lines[i + 1].strip() == "pass"
    ):
        indent = line[: len(line) - len(line.lstrip())]
        result.append(f"{indent}except Exception:\n")
        result.append(
            f'{indent}    logger.warning("ghost_vfs: operation skipped at %s", __import__("sys")._getframe(1).f_code.co_filename, exc_info=True)\n'
        )
        i += 2
        continue
    result.append(line)
    i += 1
text = "".join(result)
p.write_text(text, encoding="utf-8")

# ========================= security.py =========================
p = pathlib.Path(r"D:\cyber security test pipeline - Copy\src\dashboard\fastapi\security.py")
text = p.read_text(encoding="utf-8")
if "from src.infrastructure.db.sqlite_utils import" not in text:
    text = text.replace(
        "import sqlite3\n",
        "import sqlite3\nfrom src.infrastructure.db.sqlite_utils import safe_close\n",
    )
old = """    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=_CONNECT_TIMEOUT_SECONDS)
        try:
            conn.execute(f"PRAGMA busy_timeout={_BUSY_TIMEOUT_MS}")
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
        except Exception:
            conn.close()
            raise
        return conn"""
new = """    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=_CONNECT_TIMEOUT_SECONDS)
        try:
            conn.execute(f"PRAGMA busy_timeout={_BUSY_TIMEOUT_MS}")
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
        except Exception:
            try:
                conn.close()
            except sqlite3.ProgrammingError:
                pass
            raise
        return conn"""
if old in text:
    text = text.replace(old, new)
p.write_text(text, encoding="utf-8")

# ========================= telemetry_store.py =========================
p = pathlib.Path(
    r"D:\cyber security test pipeline - Copy\src\learning\repositories\telemetry_store.py"
)
text = p.read_text(encoding="utf-8")
# fix bare except close around line 132, 142
old = """        if hasattr(self._local, "conn") and self._local.conn:
            try:
                self._local.conn.close()
            except Exception:  # noqa: S110
                pass
            self._local.conn = None

        from .base import BaseRepo

        with BaseRepo._lock:
            for conn in list(BaseRepo._connections):
                try:
                    conn.close()
                except Exception:  # noqa: S110
                    pass
            BaseRepo._connections.clear()"""
new = """        if hasattr(self._local, "conn") and self._local.conn:
            try:
                self._local.conn.close()
            except sqlite3.ProgrammingError:
                pass
            except Exception:  # noqa: S110
                pass
            self._local.conn = None

        from .base import BaseRepo

        with BaseRepo._lock:
            for conn in list(BaseRepo._connections):
                try:
                    conn.close()
                except sqlite3.ProgrammingError:
                    pass
                except Exception:  # noqa: S110
                    pass
            BaseRepo._connections.clear()"""
if old in text:
    text = text.replace(old, new)
p.write_text(text, encoding="utf-8")

# ========================= tool_execution.py =========================
p = pathlib.Path(r"D:\cyber security test pipeline - Copy\src\pipeline\services\tool_execution.py")
text = p.read_text(encoding="utf-8")
if "import time" not in text or "\nimport time\n" not in text:
    text = text.replace("import os\n", "import os\nimport time\n", 1)
old = "_CIRCUIT_BREAKERS: dict[str, CircuitBreaker] = {}"
new = """_CIRCUIT_BREAKERS: dict[str, CircuitBreaker] = {}
# TTL eviction: prune stale circuit-breaker entries on each access (_CIRCUIT_BREAKERS_TTL_SECONDS)
_CIRCUIT_BREAKER_LAST_PRUNED: float = 0.0
_CIRCUIT_BREAKERS_TTL_SECONDS: int = 3600"""
text = text.replace(old, new)
if "def get_circuit_breaker" in text:
    old_fn = """def get_circuit_breaker(tool_name: str) -> CircuitBreaker:
    if tool_name not in _CIRCUIT_BREAKERS:
        _CIRCUIT_BREAKERS[tool_name] = CircuitBreaker()
    return _CIRCUIT_BREAKERS[tool_name]"""
    new_fn = """def get_circuit_breaker(tool_name: str) -> CircuitBreaker:
    global _CIRCUIT_BREAKER_LAST_PRUNED
    now = time.monotonic()
    if now - _CIRCUIT_BREAKER_LAST_PRUNED > _CIRCUIT_BREAKERS_TTL_SECONDS:
        _CIRCUIT_BREAKER_LAST_PRUNED = now
        for name in list(_CIRCUIT_BREAKERS):
            cb = _CIRCUIT_BREAKERS[name]
            # Drop breakers whose state is already open (no callers) or idle for > TTL
            if getattr(cb, 'state', '') == "OPEN" and (now - getattr(cb, 'last_state_change', 0)) > _CIRCUIT_BREAKERS_TTL_SECONDS:
                _CIRCUIT_BREAKERS.pop(name, None)
    if tool_name not in _CIRCUIT_BREAKERS:
        _CIRCUIT_BREAKERS[tool_name] = CircuitBreaker()
    return _CIRCUIT_BREAKERS[tool_name]"""
    text = text.replace(old_fn, new_fn)
p.write_text(text, encoding="utf-8")

# ========================= proc_pool.py =========================
p = pathlib.Path(r"D:\cyber security test pipeline - Copy\src\core\frontier\proc_pool.py")
text = p.read_text(encoding="utf-8")
if "import time" not in text:
    text = text.replace("import sys\n", "import sys\nimport time\n")
old = "self._task_receipts: dict[str, ProcessTaskReceipt] = {}"
new = "self._task_receipts: dict[str, ProcessTaskReceipt] = {}\n        self._last_receipt_prune: float = 0.0"
text = text.replace(old, new)
# prune callsites for receive/release
text = text.replace(
    '        stable_task_id = task_id or stable_digest({"tool": tool_name, "task": task_data})\n        receipt = self._task_receipts.get(stable_task_id)',
    '        stable_task_id = task_id or stable_digest({"tool": tool_name, "task": task_data})\n        self._prune_stale_receipts()\n        receipt = self._task_receipts.get(stable_task_id)',
)
text = text.replace(
    '        stable_task_id = task_id or stable_digest({"tool": tool_name, "task": repr(task_obj)})\n        receipt = self._task_receipts.get(stable_task_id)',
    '        stable_task_id = task_id or stable_digest({"tool": tool_name, "task": repr(task_obj)})\n        self._prune_stale_receipts()\n        receipt = self._task_receipts.get(stable_task_id)',
)
# Insert the helper before recovery_receipts
if "_prune_stale_receipts" not in text:
    insert_point = text.find("    def recovery_receipts(self)")
    if insert_point == -1:
        insert_point = len(text)
    helper = """    _RECEIPT_TTL_SECONDS = 3600

    def _prune_stale_receipts(self) -> None:
        now = time.monotonic()
        if now - self._last_receipt_prune < self._RECEIPT_TTL_SECONDS:
            return
        self._last_receipt_pruned = now
        for tid in list(self._task_receipts):
            receipt = self._task_receipts[tid]
            updated = getattr(receipt, "updated_at", None)
            if updated and isinstance(updated, float) and (now - updated) > self._RECEIPT_TTL_SECONDS:
                self._task_receipts.pop(tid, None)

"""
    text = text[:insert_point] + helper + text[insert_point:]
p.write_text(text, encoding="utf-8")
print("patches applied")
