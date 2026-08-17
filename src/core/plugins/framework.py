from __future__ import annotations

import abc
import asyncio
import logging
from abc import abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import TypeVar

logger = logging.getLogger(__name__)

T = TypeVar("T")


class PluginStatus(Enum):
    DISCOVERED = "discovered"
    LOADING = "loading"
    LOADED = "loaded"
    FAILED = "failed"
    UNLOADED = "unloaded"


@dataclass
class PluginMetadata:
    name: str
    version: str
    description: str = ""
    author: str = ""
    capabilities: list[str] = field(default_factory=list)
    requires: list[str] = field(default_factory=list)  # Other plugin names
    config_schema: dict = field(default_factory=dict)  # JSON schema for config
    status: PluginStatus = PluginStatus.DISCOVERED
    error: str | None = None


class Plugin(abc.ABC):
    """Base class for all plugins."""

    def __init__(self, config: dict | None = None):
        self.config = config or {}
        self._metadata: PluginMetadata | None = None

    @property
    @abstractmethod
    def metadata(self) -> PluginMetadata:
        """Return plugin metadata."""
        ...

    @abstractmethod
    async def initialize(self) -> None:
        """Initialize the plugin. Called once after loading."""
        ...

    @abstractmethod
    async def shutdown(self) -> None:
        """Cleanup resources. Called during unload."""
        ...


class PluginRegistry:
    """Registry for discovering, loading, and managing plugins."""

    def __init__(self):
        self._plugins: dict[str, Plugin] = {}
        self._metadata: dict[str, PluginMetadata] = {}
        self._factories: dict[str, Callable[[dict], Plugin]] = {}
        self._lock = asyncio.Lock()

    def register_factory(self, name: str, factory: Callable[[dict], Plugin]) -> None:
        """Register a plugin factory."""
        self._factories[name] = factory

    async def load(self, name: str, config: dict | None = None) -> Plugin:
        """Load and initialize a plugin."""
        async with self._lock:
            if name in self._plugins:
                return self._plugins[name]

            factory = self._factories.get(name)
            if not factory:
                raise ValueError(f"No factory registered for plugin: {name}")

            plugin = factory(config or {})
            meta = plugin.metadata
            meta.name = name
            meta.status = PluginStatus.LOADING

            try:
                await plugin.initialize()
                meta.status = PluginStatus.LOADED
                self._plugins[name] = plugin
                self._metadata[name] = meta
                logger.info("Plugin loaded: %s", name)
                return plugin
            except Exception as e:
                meta.status = PluginStatus.FAILED
                meta.error = str(e)
                logger.exception("Failed to load plugin %s: %s", name, e)
                raise

    async def unload(self, name: str) -> None:
        """Unload a plugin."""
        async with self._lock:
            plugin = self._plugins.pop(name, None)
            if plugin:
                meta = self._metadata.get(name)
                if meta:
                    meta.status = PluginStatus.UNLOADED
                try:
                    await plugin.shutdown()
                except Exception as e:
                    logger.warning("Error unloading plugin %s: %s", name, e)
                logger.info("Plugin unloaded: %s", name)

    async def reload(self, name: str) -> Plugin:
        """Reload a plugin with current config."""
        await self.unload(name)
        return await self.load(name, self._metadata.get(name, PluginMetadata(name="", version="")).config_schema)

    def get(self, name: str) -> Plugin | None:
        return self._plugins.get(name)

    def list_plugins(self) -> list[PluginMetadata]:
        return list(self._metadata.values())

    def get_loaded_plugins(self) -> list[str]:
        return [name for name, meta in self._metadata.items() if meta.status == PluginStatus.LOADED]


# Global registry
_plugin_registry: PluginRegistry | None = None


def get_plugin_registry() -> PluginRegistry:
    global _plugin_registry
    if _plugin_registry is None:
        _plugin_registry = PluginRegistry()
    return _plugin_registry
