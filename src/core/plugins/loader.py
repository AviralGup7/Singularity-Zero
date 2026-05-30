from __future__ import annotations

import logging
import os
import threading
from pathlib import Path
from typing import Any

from src.core.plugins.registry import register_plugin, unregister_plugin
from src.core.plugins.sandbox import ProcessSandboxCallable
from src.core.plugins.sdk import (
    DynamicPluginRecord,
    PluginManifest,
    PluginValidationError,
    load_manifest_from_source,
)

DYNAMIC_PLUGIN = "dynamic_plugin"
PLUGIN_WATCH_ENV = "CYBER_PLUGIN_DIRS"

_KIND_TO_REGISTRY = {
    "scanner": "scanner",
    "validator": "validator",
    "enrichment": "enrichment_provider",
    "exporter": "exporter",
    "recon": "recon_provider",
}

logger = logging.getLogger(__name__)


class DynamicPluginCatalog:
    """Discovers, validates, registers, and hot-reloads manifest-based plugins."""

    def __init__(self, watched_dirs: tuple[Path, ...] | None = None) -> None:
        self.watched_dirs = watched_dirs or default_plugin_dirs()
        self._lock = threading.RLock()
        self._records: dict[str, DynamicPluginRecord] = {}
        self._invalid: dict[str, PluginManifest] = {}
        self._file_signatures: dict[Path, tuple[int, int]] = {}
        self._registered: dict[str, tuple[str, str]] = {}
        self._watch_started = False

    def refresh(self) -> tuple[DynamicPluginRecord, ...]:
        with self._lock:
            seen: set[Path] = set()
            changed = False
            for plugin_file in self._iter_plugin_files():
                seen.add(plugin_file)
                signature = self._signature(plugin_file)
                if self._file_signatures.get(plugin_file) == signature:
                    continue
                changed = True
                self._file_signatures[plugin_file] = signature
                self._load_one(plugin_file)

            removed = set(self._file_signatures) - seen
            for path in removed:
                changed = True
                self._file_signatures.pop(path, None)
                self._remove_path(path)

            if changed:
                _invalidate_analysis_cache()
            return tuple(sorted(self._records.values(), key=lambda record: record.manifest.id))

    def records(self) -> tuple[DynamicPluginRecord, ...]:
        self.refresh()
        with self._lock:
            return tuple(sorted(self._records.values(), key=lambda record: record.manifest.id))

    def invalid_manifests(self) -> tuple[PluginManifest, ...]:
        self.refresh()
        with self._lock:
            return tuple(sorted(self._invalid.values(), key=lambda manifest: manifest.id))

    def as_payload(self) -> dict[str, Any]:
        return {
            "plugins": [record.to_dict() for record in self.records()],
            "invalid": [manifest.to_dict() for manifest in self.invalid_manifests()],
            "watched_dirs": [str(path) for path in self.watched_dirs],
        }

    def start_watcher(self) -> None:
        with self._lock:
            if self._watch_started:
                return
            self._watch_started = True

        thread = threading.Thread(
            target=self._watch_loop, name="dynamic-plugin-watcher", daemon=True
        )
        thread.start()

    def _watch_loop(self) -> None:
        try:
            from watchfiles import watch
        except Exception:
            return

        directories = [str(path) for path in self.watched_dirs if path.exists()]
        if not directories:
            return
        for _changes in watch(*directories, recursive=False):
            self.refresh()

    def _iter_plugin_files(self) -> tuple[Path, ...]:
        files: list[Path] = []
        for directory in self.watched_dirs:
            if not directory.exists() or not directory.is_dir():
                continue
            files.extend(
                path.resolve()
                for path in directory.glob("*.py")
                if not path.name.startswith("_") and path.name != "__init__.py"
            )
        return tuple(sorted(set(files)))

    def _load_one(self, path: Path) -> None:
        self._remove_path(path)
        try:
            manifest = load_manifest_from_source(path)
            if manifest is None:
                return
            stat = path.stat()
            record = DynamicPluginRecord(
                manifest=manifest, path=path, mtime_ns=stat.st_mtime_ns, size=stat.st_size
            )
            self._records[manifest.id] = record
            self._register(record)
        except (OSError, SyntaxError, PluginValidationError, ValueError) as exc:
            key = str(path)
            self._invalid[key] = PluginManifest(
                id=f"invalid.{path.stem.replace('_', '-')}",
                name=path.name,
                version="0",
                kind="analysis",
                description="Invalid dynamic plugin",
                source_path=str(path),
                status="invalid",
                errors=(str(exc),),
            )

    def _remove_path(self, path: Path) -> None:
        self._invalid.pop(str(path), None)
        for plugin_id, record in tuple(self._records.items()):
            if record.path != path:
                continue
            registration = self._registered.pop(plugin_id, None)
            if registration is not None:
                unregister_plugin(*registration)
            unregister_plugin(DYNAMIC_PLUGIN, record.manifest.key)
            self._records.pop(plugin_id, None)

    def _register(self, record: DynamicPluginRecord) -> None:
        manifest = record.manifest
        register_plugin(DYNAMIC_PLUGIN, manifest.key, manifest=manifest.to_dict())(record)
        if manifest.kind == "analysis":
            self._register_analysis(record)
            return

        registry_kind = _KIND_TO_REGISTRY.get(manifest.kind)
        if registry_kind is None:
            return
        provider = ProcessSandboxCallable(manifest, record.path)
        register_plugin(registry_kind, manifest.key, manifest=manifest.to_dict(), dynamic=True)(
            provider
        )
        self._registered[manifest.id] = (registry_kind, manifest.key)

    def _register_analysis(self, record: DynamicPluginRecord) -> None:
        from src.analysis.plugins._main import DETECTOR_SPEC
        from src.analysis.plugins.base import spec

        manifest = record.manifest
        plugin_spec = spec(
            manifest.key,
            manifest.name,
            manifest.description,
            manifest.group,
            slug=manifest.slug,
            enabled_by_default=manifest.enabled_by_default,
            source="dynamic",
        )
        register_plugin(DETECTOR_SPEC, manifest.key, manifest=manifest.to_dict(), dynamic=True)(
            plugin_spec
        )
        self._registered[manifest.id] = (DETECTOR_SPEC, manifest.key)

    @staticmethod
    def _signature(path: Path) -> tuple[int, int]:
        stat = path.stat()
        return stat.st_mtime_ns, stat.st_size


def default_plugin_dirs() -> tuple[Path, ...]:
    repo_root = Path(__file__).resolve().parents[3]
    configured = tuple(
        Path(part).expanduser().resolve()
        for part in os.environ.get(PLUGIN_WATCH_ENV, "").split(os.pathsep)
        if part.strip()
    )
    builtins = (
        repo_root / ".pipeline" / "plugins",
        repo_root / "src" / "core" / "frontier" / "plugins",
        repo_root / "src" / "analysis" / "plugins",
        repo_root / "src" / "execution" / "validators" / "validators",
        repo_root / "src" / "core" / "plugins",
    )
    return configured + builtins


_CATALOG = DynamicPluginCatalog()


def get_dynamic_plugin_catalog() -> DynamicPluginCatalog:
    return _CATALOG


def refresh_dynamic_plugins() -> tuple[DynamicPluginRecord, ...]:
    return _CATALOG.refresh()


def start_dynamic_plugin_watcher() -> None:
    _CATALOG.start_watcher()


def dynamic_plugin_payload() -> dict[str, Any]:
    return _CATALOG.as_payload()


def _invalidate_analysis_cache() -> None:
    try:
        from src.analysis.plugins._main import invalidate_analysis_plugin_cache

        invalidate_analysis_plugin_cache()
    except Exception as exc:
        logger.debug("Unable to invalidate analysis plugin cache: %s", exc)
