from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from src.core.capabilities import (
    CapabilityManifest,
    CrawlerProvider,
    HttpProbeProvider,
    ReconProvider,
    TemplateScanner,
    ToolExecutionContext,
)
from src.recon.live_hosts import probe_live_hosts
from src.recon.subdomains import enumerate_subdomains
from src.recon.urls import collect_urls

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class SubdomainReconProvider(ReconProvider):
    def collect(
        self, scope_entries: list[str], context: ToolExecutionContext | None = None, **kwargs: Any
    ) -> set[str]:
        ctx = context or ToolExecutionContext(config=kwargs.get("config"))
        config = ctx.config
        skip_crtsh = bool(kwargs.get("skip_crtsh", False))
        if config is None:
            return set()
        return set(enumerate_subdomains(scope_entries, config, skip_crtsh))


@dataclass(slots=True)
class DefaultHttpProbeProvider(HttpProbeProvider):
    def probe(
        self, hosts: list[str], context: ToolExecutionContext | None = None, **kwargs: Any
    ) -> tuple[list[dict[str, Any]], set[str]]:
        ctx = context or ToolExecutionContext(config=kwargs.get("config"))
        config = ctx.config
        progress_callback = kwargs.get("progress_callback")
        force_recheck = bool(kwargs.get("force_recheck", False))
        if config is None:
            return [], set()
        return probe_live_hosts(
            set(hosts),
            config,
            progress_callback,
            force_recheck=force_recheck,
        )


@dataclass(slots=True)
class DefaultCrawlerProvider(CrawlerProvider):
    def crawl(
        self, seeds: list[str], context: ToolExecutionContext | None = None, **kwargs: Any
    ) -> set[str]:
        ctx = context or ToolExecutionContext(config=kwargs.get("config"))
        config = ctx.config
        scope_entries = kwargs.get("scope_entries") or seeds
        progress_callback = kwargs.get("progress_callback")
        stage_meta = kwargs.get("stage_meta")
        if config is None:
            return set()
        return set(
            collect_urls(
                set(seeds),
                scope_entries,
                config,
                progress_callback=progress_callback,
                stage_meta=stage_meta,
            )
        )


@dataclass(slots=True)
class NoopTemplateScanner(TemplateScanner):
    def scan_templates(
        self,
        targets: list[str],
        templates: list[str],
        context: ToolExecutionContext | None = None,
        **kwargs: Any,
    ) -> list[dict[str, Any]]:
        return [
            {
                "target": target,
                "template": template,
                "status": "not_implemented",
            }
            for target in targets
            for template in templates
        ]


# Resource metrics for default capabilities
RECON_MANIFEST = CapabilityManifest(
    estimated_duration_seconds=60.0,
    memory_mb=256.0,
    network_calls_per_target=10,
    supports_checkpoint_resume=True,
    version_requirements={"subfinder": ">=2.0.0"},
)

PROBE_MANIFEST = CapabilityManifest(
    estimated_duration_seconds=30.0,
    memory_mb=128.0,
    network_calls_per_target=50,
    supports_checkpoint_resume=True,
    version_requirements={"httpx": ">=1.0.0"},
)

CRAWLER_MANIFEST = CapabilityManifest(
    estimated_duration_seconds=120.0,
    memory_mb=512.0,
    network_calls_per_target=100,
    supports_checkpoint_resume=False,
    version_requirements={},
)

SCANNER_MANIFEST = CapabilityManifest(
    estimated_duration_seconds=5.0,
    memory_mb=64.0,
    network_calls_per_target=0,
    supports_checkpoint_resume=True,
    version_requirements={},
)


class CapabilityRegistry:
    """Registry managing capability providers and their manifests with setuptools entry_points support."""

    def __init__(self) -> None:
        self._providers: dict[str, Any] = {}
        self._manifests: dict[str, CapabilityManifest] = {}
        self._loaded_entry_points: bool = False

    def register(self, name: str, provider: Any, manifest: CapabilityManifest) -> None:
        key = name.strip().lower()
        self._providers[key] = provider
        self._manifests[key] = manifest

    def get_provider(self, name: str) -> Any:
        self._ensure_entry_points_loaded()
        key = name.strip().lower()
        if key not in self._providers:
            raise KeyError(f"Unknown capability provider: {name}")
        return self._providers[key]

    def get_manifest(self, name: str) -> CapabilityManifest:
        self._ensure_entry_points_loaded()
        key = name.strip().lower()
        if key not in self._manifests:
            raise KeyError(f"Unknown capability provider: {name}")
        return self._manifests[key]

    def list_capabilities(self) -> list[str]:
        self._ensure_entry_points_loaded()
        return list(self._providers.keys())

    def _ensure_entry_points_loaded(self) -> None:
        if self._loaded_entry_points:
            return
        self._loaded_entry_points = True
        try:
            from importlib.metadata import entry_points

            eps = entry_points(group="cyber_security_pipeline.capabilities")

            for ep in eps:
                try:
                    plugin_factory = ep.load()
                    provider, manifest = plugin_factory()
                    self.register(ep.name, provider, manifest)
                except Exception as exc:
                    logger.warning("Failed to load capability entry point %s: %s", ep.name, exc)
        except Exception as exc:
            logger.debug("Failed to lookup entry points: %s", exc)


CAPABILITY_REGISTRY = CapabilityRegistry()

# Register standard built-in providers
CAPABILITY_REGISTRY.register("recon_provider", SubdomainReconProvider(), RECON_MANIFEST)
CAPABILITY_REGISTRY.register("http_probe_provider", DefaultHttpProbeProvider(), PROBE_MANIFEST)
CAPABILITY_REGISTRY.register("crawler_provider", DefaultCrawlerProvider(), CRAWLER_MANIFEST)
CAPABILITY_REGISTRY.register("template_scanner", NoopTemplateScanner(), SCANNER_MANIFEST)

# Backwards compatibility dictionary interface
CAPABILITY_PROVIDERS: dict[str, Any] = {
    "recon_provider": CAPABILITY_REGISTRY.get_provider("recon_provider"),
    "http_probe_provider": CAPABILITY_REGISTRY.get_provider("http_probe_provider"),
    "crawler_provider": CAPABILITY_REGISTRY.get_provider("crawler_provider"),
    "template_scanner": CAPABILITY_REGISTRY.get_provider("template_scanner"),
}


def resolve_capability(name: str) -> Any:
    return CAPABILITY_REGISTRY.get_provider(name)
