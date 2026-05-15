from __future__ import annotations

from typing import Any, Protocol


class TemplateScanner(Protocol):
    def scan_templates(
        self, targets: list[str], templates: list[str], **kwargs: Any
    ) -> list[dict[str, Any]]: ...


class ReconProvider(Protocol):
    def collect(self, scope_entries: list[str], **kwargs: Any) -> set[str]: ...


class HttpProbeProvider(Protocol):
    def probe(self, hosts: list[str], **kwargs: Any) -> tuple[list[dict[str, Any]], set[str]]: ...


class CrawlerProvider(Protocol):
    def crawl(self, seeds: list[str], **kwargs: Any) -> set[str]: ...
