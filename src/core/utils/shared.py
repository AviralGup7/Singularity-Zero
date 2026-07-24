"""Shared URL and text normalization utilities.

Provides functions for normalizing scope entries, URLs, and parsing
plain text line lists into deduplicated sets.

Also provides the module-level self-description system: ``ModuleMeta``,
``register_module_meta()``, and helpers that every ``src/*/__init__.py``
uses to publish its version, purpose, public API surface, and a runtime
health-check.  This makes each module independently updatable, auditable,
and testable without cross-module coupling.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse

logger = logging.getLogger(__name__)

__all__ = [
    "ModuleMeta",
    "ModuleRegistry",
    "GLOBAL_MODULE_REGISTRY",
    "register_module_meta",
    "get_module_meta",
    "list_registered_modules",
    "normalize_scope_entry",
    "normalize_url",
    "parse_plain_lines",
]


# ---------------------------------------------------------------------------
# Module self-description system
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ModuleMeta:
    """Immutable description of a pipeline module published in its ``__init__.py``.

    Each ``src/<module>/__init__.py`` should define a ``MODULE_META`` dict
    (or directly instantiate ``ModuleMeta``) and then call
    ``register_module_meta(MODULE_META)`` so the registry always has an
    up-to-date picture of the module graph.

    Attributes:
        name: Short module identifier matching the directory name
              (e.g. ``"analysis"``, ``"recon"``).
        version: Semver-compatible module version string.
        description: One-sentence human description of module purpose.
        layer: Architectural layer the module belongs to (see
               ``src/core/contracts/module_interfaces.ModuleLayer``).
        submodules: Tuple of sub-package names exposed by this module.
        public_api: Tuple of top-level symbol names this module re-exports.
        depends_on: Tuple of other module names this module imports.
        entry_points: Tuple of console_script names this module provides.
        health_check: Name of a zero-argument function in this module's
            ``__init__.py`` that returns a ``dict[str, Any]`` health status.
            Omit or set to ``""`` if not applicable.
    """

    name: str
    version: str
    description: str
    layer: str = "unknown"
    submodules: tuple[str, ...] = ()
    public_api: tuple[str, ...] = ()
    depends_on: tuple[str, ...] = ()
    entry_points: tuple[str, ...] = ()
    health_check: str = ""


class ModuleRegistry:
    """Thread-safe registry of all pipeline modules.

    Populated automatically when each ``src/*/__init__.py`` calls
    ``register_module_meta`` at import time.  Consumers can call
    ``list_registered_modules`` or ``get_module_meta`` to inspect the
    module graph without importing every sub-package.

    Usage::

        from src.core.utils.shared import GLOBAL_MODULE_REGISTRY
        meta = GLOBAL_MODULE_REGISTRY.get("analysis")
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._registry: dict[str, ModuleMeta] = {}

    def register(self, meta: ModuleMeta) -> None:
        with self._lock:
            self._registry[meta.name] = meta
            logger.debug("Registered module meta: %s v%s", meta.name, meta.version)

    def get(self, name: str) -> ModuleMeta | None:
        with self._lock:
            return self._registry.get(name)

    def all(self) -> dict[str, ModuleMeta]:
        with self._lock:
            return dict(self._registry)

    def keys(self) -> list[str]:
        with self._lock:
            return list(self._registry.keys())


GLOBAL_MODULE_REGISTRY: ModuleRegistry = ModuleRegistry()


def register_module_meta(meta: ModuleMeta | dict[str, Any]) -> None:
    """Register module metadata in the global registry.

    Accepts either a ``ModuleMeta`` instance or a plain ``dict`` that can
    be passed to the ``ModuleMeta`` constructor.  Called from each module's
    ``__init__.py`` at import time.

    Args:
        meta: ModuleMeta instance or dict with ModuleMeta-compatible fields.
    """
    if isinstance(meta, dict):
        meta = ModuleMeta(**{k: v for k, v in meta.items() if k in ModuleMeta.__dataclass_fields__})
    GLOBAL_MODULE_REGISTRY.register(meta)


def get_module_meta(name: str) -> ModuleMeta | None:
    """Look up the ``ModuleMeta`` for *name*.

    Args:
        name: Module directory name (e.g. ``"analysis"``).

    Returns:
        ModuleMeta if registered, None otherwise.
    """
    return GLOBAL_MODULE_REGISTRY.get(name)


def list_registered_modules() -> list[ModuleMeta]:
    """Return a snapshot of all currently registered module metadata.

    Returns:
        List of ModuleMeta instances sorted by module name.
    """
    return sorted(GLOBAL_MODULE_REGISTRY.all().values(), key=lambda m: m.name)


# ---------------------------------------------------------------------------
# URL / text normalization (unchanged)
# ---------------------------------------------------------------------------


def normalize_scope_entry(entry: str) -> str:
    """Remove wildcard prefix from a scope entry (e.g., '*.example.com' -> 'example.com').

    Args:
        entry: Scope entry string, optionally prefixed with '*.'.

    Returns:
        Scope entry with wildcard prefix removed if present.
    """
    return entry[2:] if entry.startswith("*.") else entry


def normalize_url(url: str) -> str:
    """
    Frontier URL Normalizer.
    Lowercases, sorts query params, strips trailing slashes, resolves path traversals,
    and normalizes standard ports for perfect distributed deduplication.
    """
    candidate = url.strip()
    if not candidate:
        return ""

    try:
        raw_parsed = urlparse(candidate if "://" in candidate else f"https://{candidate}")
        scheme = (raw_parsed.scheme or "https").lower()
        netloc = raw_parsed.netloc.lower() or raw_parsed.path.lower()

        # 1. Standard Port Normalization
        if ":" in netloc:
            host, port = netloc.rsplit(":", 1)
            if (scheme == "http" and port == "80") or (scheme == "https" and port == "443"):
                netloc = host

        # 2. Path Canonicalization (Collapse slashes and resolve traversals)
        path = raw_parsed.path if netloc else ""
        import os

        cleaned_path = os.path.normpath(path).replace("\\", "/")  # cross-platform safety
        # Bug #9 fix: the previous code had a dead ``elif path.endswith("/")``
        # branch that only contained a ``pass`` statement, so the documented
        # "preserve trailing slash" behaviour never ran. Trailing slashes
        # were silently stripped on every URL canonicalization. We now
        # actually preserve a trailing slash when the original path had
        # one and ``normpath`` collapsed it away.
        if cleaned_path == ".":
            cleaned_path = ""
        if path.endswith("/") and not cleaned_path.endswith("/"):
            cleaned_path = cleaned_path + "/" if cleaned_path else "/"

        # 3. Query Normalization
        normalized_query = urlencode(
            sorted(parse_qsl(raw_parsed.query, keep_blank_values=True)), doseq=True
        )

        normalized = f"{scheme}://{netloc}"
        if cleaned_path and cleaned_path != "/":
            normalized += cleaned_path
        if normalized_query:
            normalized += f"?{normalized_query}"
        return normalized
    except (ValueError, AttributeError) as exc:
        logger.debug("Frontier: Failed to normalize URL %r: %s", url, exc)
        return candidate


def parse_plain_lines(text: str) -> set[str]:
    """Parse plain text lines into a deduplicated set of normalized values.

    Lines containing '://' or '/' are treated as URLs and normalized.
    Other lines are lowercased and stripped.

    Args:
        text: Multi-line text to parse.

    Returns:
        Set of normalized values.
    """
    values = set()
    for line in text.splitlines():
        try:
            normalized = (
                normalize_url(line) if "://" in line or "/" in line else line.strip().lower()
            )
            if normalized:
                values.add(normalized)
        except Exception as exc:
            logger.debug("Skipping malformed line %r: %s", line, exc)
    return values
