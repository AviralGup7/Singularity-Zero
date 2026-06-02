import pathlib

# cache_backend.py – replace bare conn.close() with safe_close guard in _get_conn
p = pathlib.Path(r"D:\cyber security test pipeline - Copy\src\pipeline\cache_backend.py")
text = p.read_text(encoding="utf-8")
text = text.replace(
    "        except Exception:\n            conn.close()\n            raise",
    "        except Exception:\n            try:\n                conn.close()\n            except sqlite3.ProgrammingError:\n                pass\n            raise",
)
p.write_text(text, encoding="utf-8")

# job_store.py – fix imports order and safe_close in close() is already done but _get_conn pragma
p = pathlib.Path(r"D:\cyber security test pipeline - Copy\src\dashboard\job_store.py")
text = p.read_text(encoding="utf-8")
# remove spurious marker/flag from base.py if present
if "safe_close.__self_flag__ = True" in text:
    text = text.replace("safe_close.__self_flag__ = True\n", "")
# fix pragma failure block
old = """            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute(f"PRAGMA busy_timeout={_BUSY_TIMEOUT_MS}")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA foreign_keys=ON")"""
new = """            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute(f"PRAGMA busy_timeout={_BUSY_TIMEOUT_MS}")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA foreign_keys=ON")"""
if old in text:
    text = text.replace(old, new)
# the pragma try/except is already in place - keep it
p.write_text(text, encoding="utf-8")

print("done")
