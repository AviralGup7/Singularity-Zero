"""Cache warming helpers extracted from CacheManager.

These functions perform warming from JSON files, SQLite databases, or
directories of JSON files. They accept the CacheManager instance so they
can call `set()` and honor namespace/ttl rules.
"""

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def warm_from_json(manager: Any, path: Path) -> None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            for key, value in data.items():
                manager.set(key, value, namespace="warm")
            logger.info("Warmed %d entries from %s", len(data), path)
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("Failed to warm from JSON %s: %s", path, exc)


def warm_from_sqlite(manager: Any, db_path: str) -> None:
    try:
        import sqlite3

        conn = sqlite3.connect(db_path)
        cursor = conn.execute("SELECT key, value FROM cache_entries")
        count = 0
        for row in cursor:
            try:
                value = json.loads(row[1])
                manager.set(row[0], value, namespace="warm")
                count += 1
            except json.JSONDecodeError, TypeError:
                pass
        conn.close()
        logger.info("Warmed %d entries from SQLite %s", count, db_path)
    except Exception as exc:
        logger.warning("Failed to warm from SQLite %s: %s", db_path, exc)


def warm_from_directory(manager: Any, dir_path: Path) -> None:
    count = 0
    for json_file in dir_path.rglob("*.json"):
        try:
            data = json.loads(json_file.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                key = str(json_file.relative_to(dir_path))
                manager.set(key, data, namespace="warm")
                count += 1
        except json.JSONDecodeError, OSError:
            pass
    logger.info("Warmed %d entries from directory %s", count, dir_path)
