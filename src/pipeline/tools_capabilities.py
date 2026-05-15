from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from src.core.capabilities import CrawlerProvider, HttpProbeProvider, ReconProvider, TemplateScanner
from src.recon.live_hosts import probe_live_hosts
from src.recon.subdomains import enumerate_subdomains
from src.recon.urls import collect_urls


@dataclass(slots=True)
class SubdomainReconProvider(ReconProvider):
    def collect(self, scope_entries: list[str], **kwargs: Any) -> set[str]:
        config = kwargs.get("config")
        skip_crtsh = bool(kwargs.get("skip_crtsh", False))
        if config is None:
            return set()
        return set(enumerate_subdomains(scope_entries, config, skip_crtsh))


@dataclass(slots=True)
class DefaultHttpProbeProvider(HttpProbeProvider):
    def probe(self, hosts: list[str], **kwargs: Any) -> tuple[list[dict[str, Any]], set[str]]:
        config = kwargs.get("config")
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
    def crawl(self, seeds: list[str], **kwargs: Any) -> set[str]:
        config = kwargs.get("config")
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
        self, targets: list[str], templates: list[str], **kwargs: Any
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


CAPABILITY_PROVIDERS: dict[str, Any] = {
    "recon_provider": SubdomainReconProvider(),
    "http_probe_provider": DefaultHttpProbeProvider(),
    "crawler_provider": DefaultCrawlerProvider(),
    "template_scanner": NoopTemplateScanner(),
}


def resolve_capability(name: str) -> Any:
    key = name.strip().lower()
    if key not in CAPABILITY_PROVIDERS:
        raise KeyError(f"Unknown capability provider: {name}")
    return CAPABILITY_PROVIDERS[key]
