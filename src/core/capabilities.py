from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass(frozen=True, slots=True)
class ToolExecutionContext:
    """Execution context containing paths, environments, and sandbox constraints for a tool."""

    resolved_paths: dict[str, str] = field(default_factory=dict)
    env: dict[str, str] = field(default_factory=dict)
    sandbox_constraints: dict[str, Any] = field(default_factory=dict)
    config: Any = None


@dataclass(frozen=True, slots=True)
class CapabilityManifest:
    """Estimated performance and constraint requirements for a pipeline capability."""

    estimated_duration_seconds: float
    memory_mb: float
    network_calls_per_target: int
    supports_checkpoint_resume: bool
    version_requirements: dict[str, str] = field(default_factory=dict)


class TemplateScanner(Protocol):
    def scan_templates(
        self, targets: list[str], templates: list[str], context: ToolExecutionContext, **kwargs: Any
    ) -> list[dict[str, Any]]: ...


class ReconProvider(Protocol):
    def collect(
        self, scope_entries: list[str], context: ToolExecutionContext, **kwargs: Any
    ) -> set[str]: ...


class HttpProbeProvider(Protocol):
    def probe(
        self, hosts: list[str], context: ToolExecutionContext, **kwargs: Any
    ) -> tuple[list[dict[str, Any]], set[str]]: ...


class CrawlerProvider(Protocol):
    def crawl(self, seeds: list[str], context: ToolExecutionContext, **kwargs: Any) -> set[str]: ...


@dataclass(frozen=True, slots=True)
class SystemPluginManifest:
    """Serializable view of built-in and dynamic extension capabilities."""

    generated_by: str = "src.core.capabilities.generate_capability_manifest"
    plugin_schema_version: str = "1.0"
    providers: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    dynamic_plugins: list[dict[str, Any]] = field(default_factory=list)
    invalid_dynamic_plugins: list[dict[str, Any]] = field(default_factory=list)
    watched_dirs: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_by": self.generated_by,
            "plugin_schema_version": self.plugin_schema_version,
            "providers": self.providers,
            "dynamic_plugins": self.dynamic_plugins,
            "invalid_dynamic_plugins": self.invalid_dynamic_plugins,
            "watched_dirs": self.watched_dirs,
        }


# Backwards compatibility alias
CapabilityManifestLegacy = SystemPluginManifest


def generate_capability_manifest() -> SystemPluginManifest:
    """Build a fresh system capability/plugin manifest from the live plugin registry."""

    from src.core.plugins import list_plugins
    from src.core.plugins.loader import dynamic_plugin_payload, refresh_dynamic_plugins

    refresh_dynamic_plugins()
    provider_kinds = (
        "recon_provider",
        "scanner",
        "validator",
        "exporter",
        "enrichment_provider",
        "detector_spec",
        "dynamic_plugin",
    )
    providers: dict[str, list[dict[str, Any]]] = {}
    for kind in provider_kinds:
        providers[kind] = [
            {
                "key": registration.key,
                "metadata": registration.metadata,
                "provider": type(registration.provider).__name__,
            }
            for registration in list_plugins(kind)
        ]

    payload = dynamic_plugin_payload()
    return SystemPluginManifest(
        providers=providers,
        dynamic_plugins=payload["plugins"],
        invalid_dynamic_plugins=payload["invalid"],
        watched_dirs=payload["watched_dirs"],
    )
