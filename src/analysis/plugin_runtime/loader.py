"""Lazy import mechanism for analyzer bindings.

Bug #3: LazyRunner now caches the resolved callable after first import.
Previously, every invocation of __call__() performed importlib.import_module()
and getattr(), even though Python's module cache made the import cheap, the
attribute lookup and function call overhead was repeated 100+ times per pipeline
run. Now the resolved callable is cached on first use.
"""

from __future__ import annotations

import importlib
import threading
from typing import Any


class LazyRunner:
    """Callable that lazily imports and invokes a function from a module path.

    Bug #3: The resolved callable is cached after first import. Thread-safe
    via a lock so multiple threads can call the same LazyRunner concurrently
    without race conditions on the cache.
    """

    def __init__(self, module_path: str, attr_name: str):
        self.module_path = module_path
        self.attr_name = attr_name
        self._resolved: Any = None
        self._resolved_lock = threading.Lock()

    def __lazy_resolve__(self) -> Any:
        if self._resolved is not None:
            return self._resolved

        with self._resolved_lock:
            if self._resolved is not None:
                return self._resolved
            module = importlib.import_module(self.module_path)
            self._resolved = getattr(module, self.attr_name)
            return self._resolved

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        return self.__lazy_resolve__()(*args, **kwargs)


def _lazy_import(module_path: str, attr_name: str) -> LazyRunner:
    """Return a callable that lazily imports and returns the attribute."""
    return LazyRunner(module_path, attr_name)
