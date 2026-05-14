"""HTTP probe request template builder.

Go zero-copy template pattern translated to Python: instead of building
HTTP requests from scratch for every URL/probe combination, pre-build a
base template and mutate only the fields that change.

Patterns borrowed from Go:
- Pre-build packet/request structure with only variable fields left blank
- Patch 3-5 fields per send instead of full serialization
- Fast-path selection (use cached response vs full probe)
- Batch construction (build many requests at once for connection pooling)
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any
from urllib.parse import urlparse

import httpx


@dataclass
class ProbeTemplate:
    """Pre-built HTTP probe with only variable fields parameterized.

    Equivalent to Go's [24]byte TCP packet template where only dstIP,
    dstPort, and seq change per send.

    Usage::

        # Build once
        tmpl = ProbeTemplate.from_probes(
            method="GET",
            base_headers={"User-Agent": "...", "Accept": "*/*"},
        )

        # Send to many targets - only URL changes
        async with httpx.AsyncClient() as client:
            for url in urls:
                req = tmpl.build(url)
                await client.send(req)
    """

    method: str
    path: str = ""
    headers: dict[str, str]
    content: bytes | None = None
    params: dict[str, str] | None = None
    follow_redirects: bool = False
    timeout: float = 10.0

    __slots__ = ("method", "path", "headers", "content", "params", "follow_redirects", "timeout")

    def build(self, url: str) -> httpx.Request:
        """Build a request for a specific target URL.

        Only constructs the httpx.Request object (does not send).
        This is O(1) — no URL parsing, no header merging.
        """
        if self.path:
            parsed = urlparse(url)
            target_url = f"{parsed.scheme}://{parsed.netloc}{self.path}"
        else:
            target_url = url

        return httpx.Request(
            method=self.method,
            url=target_url,
            headers=self.headers,
            content=self.content,
            params=self.params,
        )

    def with_url_path(self, base_url: str, path: str) -> httpx.Request:
        """Build a request with a specific path on the given base URL."""
        parsed = urlparse(base_url)
        target_url = f"{parsed.scheme}://{parsed.netloc}{path}"
        return httpx.Request(
            method=self.method,
            url=target_url,
            headers=self.headers,
            content=self.content,
        )

    def clone_with_header(self, key: str, value: str) -> ProbeTemplate:
        """Create a new template with one additional header.

        Returns a new template — original is unchanged."""
        new_headers = dict(self.headers)
        new_headers[key] = value
        return replace(self, headers=new_headers)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> ProbeTemplate:
        """Build from configuration dict."""
        return cls(
            method=d.get("method", "GET"),
            path=d.get("path", ""),
            headers=d.get("headers", {}),
            content=d.get("content"),
            params=d.get("params"),
            follow_redirects=d.get("follow_redirects", False),
            timeout=d.get("timeout", 10.0),
        )


class ProbeTemplateSet:
    """A set of pre-built probe templates for batch scanning.

    Instead of building individual requests per URL per probe type,
    build templates once and dispatch to all URLs.

    Usage::

        templates = ProbeTemplateSet()
        templates.add("sqli", ProbeTemplate(method="GET", params={"id": "' OR 1=1 --"}))
        templates.add("ssrf", ProbeTemplate(method="GET", params={"url": "http://169.254.169.254"}))

        # Later, during scanning:
        for url in urls:
            for probe_name, tmpl in templates:
                req = tmpl.build(url)
                # send req...
    """

    def __init__(self) -> None:
        self._templates: dict[str, ProbeTemplate] = {}

    def add(self, name: str, template: ProbeTemplate) -> None:
        """Add a probe template."""
        self._templates[name] = template

    def get(self, name: str) -> ProbeTemplate | None:
        """Get a probe template by name."""
        return self._templates.get(name)

    def __iter__(self):
        return iter(self._templates.items())

    def __len__(self) -> int:
        return len(self._templates)

    def __contains__(self, name: str) -> bool:
        return name in self._templates

    def build_all_for_url(self, url: str) -> dict[str, httpx.Request]:
        """Build all probe requests for a single URL.

        Returns {probe_name: request} dict.
        """
        return {name: tmpl.build(url) for name, tmpl in self._templates.items()}

    def clone_with_headers(self, extra_headers: dict[str, str]) -> ProbeTemplateSet:
        """Create a new set with additional headers on all templates."""
        new_set = ProbeTemplateSet()
        for name, tmpl in self._templates.items():
            new_headers = dict(tmpl.headers)
            new_headers.update(extra_headers)
            new_set.add(name, replace(tmpl, headers=new_headers))
        return new_set

    @classmethod
    def default_probes(cls) -> ProbeTemplateSet:
        """Build a set of common security probe templates."""
        s = cls()

        # SSRF probes
        s.add(
            "ssrf_internal",
            ProbeTemplate(
                method="GET",
                params={"url": "http://169.254.169.254/latest/meta-data/"},
                headers={"User-Agent": "Mozilla/5.0"},
                timeout=5.0,
            ),
        )
        s.add(
            "ssrf_localhost",
            ProbeTemplate(
                method="GET",
                params={"url": "http://localhost:8080/"},
                headers={"User-Agent": "Mozilla/5.0"},
                timeout=5.0,
            ),
        )

        # XSS probes
        s.add(
            "xss_reflected",
            ProbeTemplate(
                method="GET",
                params={"q": "<script>alert(1)</script>"},
                headers={"User-Agent": "Mozilla/5.0"},
                timeout=10.0,
            ),
        )

        # SQLi probes
        s.add(
            "sqli_basic",
            ProbeTemplate(
                method="GET",
                params={"id": "' OR '1'='1"},
                headers={"User-Agent": "Mozilla/5.0"},
                timeout=10.0,
            ),
        )
        s.add(
            "sqli_error",
            ProbeTemplate(
                method="GET",
                params={
                    "id": "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--"
                },
                headers={"User-Agent": "Mozilla/5.0"},
                timeout=10.0,
            ),
        )

        # LFI probes
        s.add(
            "lfi_etc_passwd",
            ProbeTemplate(
                method="GET",
                params={"file": "../../../../../etc/passwd"},
                headers={"User-Agent": "Mozilla/5.0"},
                timeout=10.0,
            ),
        )

        # Command injection probes
        s.add(
            "cmd_injection",
            ProbeTemplate(
                method="GET",
                params={"host": "127.0.0.1; cat /etc/passwd"},
                headers={"User-Agent": "Mozilla/5.0"},
                timeout=10.0,
            ),
        )

        return s
