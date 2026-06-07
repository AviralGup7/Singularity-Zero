"""SPA framework detection and framework-aware URL collection.

Modern web applications are overwhelmingly Single-Page Applications
(SPAs) built on React, Vue, Svelte, Angular, Next.js, Nuxt, Remix,
Astro, etc. The standard ``<script src="...">`` extraction that
``js_discovery`` runs only finds the initial bundle — the route
definitions, API clients, and dynamic chunks live in code-split
bundles referenced by Webpack/Rollup manifests, service workers, or
dynamic ``import()`` calls that are not present in the initial HTML.

This module detects the SPA framework in use and seeds the URL
collector with the framework-specific paths that almost always exist:

* **Next.js** — ``/__next/data/`` JSON page data, ``/_next/static/``
  for build artifacts, ``/api/`` for serverless endpoints, the
  ``BUILD_ID`` file at the root, ISR ``__next_preview_data`` markers.
* **Nuxt 3** — ``/_nuxt/builds/``, ``/_nuxt/builds/meta/``, the
  ``__NUXT__`` global embedded in HTML, ``/_payload.json``.
* **Remix** — ``/build/_assets/``, ``/app/entry.client.tsx`` source
  maps in dev mode, ``/__manifest``.
* **Astro** — ``/astro-island``, ``/_astro/``, ``/@vite/``.
* **Angular / Angular Universal** — ``/ngsw-worker.js``,
  ``/ngsw.json``, ``/assets/config.json``,
  ``/sockjs-node/info`` (dev only).
* **SvelteKit** — ``/__data.json``, ``/_app/``.
* **CRA** (Create-React-App) — ``/static/js/`` chunked bundles,
  ``/asset-manifest.json``.
* **Gatsby** — ``/page-data/``, ``/app-data.json``,
  ``/static/d/`` for compiled templates.
* **Vue (non-Nuxt)** — ``/manifest.json``, ``/assets/manifest.json``.

For every detected framework the corresponding path list is returned
so the orchestrator can enqueue them for katana / httpx crawling.
Detection is purely passive — we only issue ``GET`` requests for the
highest-value framework probes (``__next/data/...``,
``/ngsw.json``, ``/manifest.json``) and otherwise just inspect
already-fetched JS / HTML content for framework signatures.
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlparse

from src.recon.js_fetcher import _fetch_text_content
from src.recon.live_hosts.discovery import _host_from_url  # noqa: F401 - re-exported
from src.recon.url_validation import is_safe_url

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Framework signatures
# ---------------------------------------------------------------------------

# Cheap-to-detect markers: each entry is a tuple of (substring,
# framework_name). We check the HTML and (already-fetched) JS bodies
# for these substrings.
_HTML_JS_SIGNATURES: tuple[tuple[str, str], ...] = (
    ("__NEXT_DATA__", "Next.js"),
    ("_next/static", "Next.js"),
    ("/_next/data", "Next.js"),
    ("__NUXT__", "Nuxt"),
    ("__nuxt", "Nuxt"),
    ("/_nuxt/builds", "Nuxt 3"),
    ("/_payload.json", "Nuxt 3"),
    ("window.__remixContext", "Remix"),
    ("window.__remixManifest", "Remix"),
    ("remix-run", "Remix"),
    ("astro-island", "Astro"),
    ("data-astro-cid", "Astro"),
    ("/_astro/", "Astro"),
    ("ngsw-worker", "Angular"),
    ("ngsw.json", "Angular"),
    ("angular.json", "Angular"),
    ("<ng-", "Angular"),
    ("__sveltekit", "SvelteKit"),
    ("svelte/internal", "SvelteKit"),
    ("/_app/immutable", "SvelteKit"),
    ("/__data.json", "SvelteKit"),
    ("react-dom", "React"),
    ("React.createElement", "React"),
    ("Vue.createApp", "Vue"),
    ("vue.runtime", "Vue"),
    ("webpackJsonp", "Webpack (bundled)"),
    ("__webpack_require__", "Webpack (bundled)"),
    ("vite/client", "Vite"),
    ("/@vite/", "Vite"),
    ("/page-data/", "Gatsby"),
    ("/app-data.json", "Gatsby"),
    ("/static/d/", "Gatsby"),
    ("/asset-manifest.json", "CRA"),
    ("/build/", "CRA / Webpack"),
    ("_buildManifest.js", "CRA"),
)

# Per-framework URL probes. For each framework we list the relative
# paths that should be fed into the URL collector if the framework is
# detected. Paths are joined against the host base URL by the caller.
_FRAMEWORK_PROBES: dict[str, list[str]] = {
    "Next.js": [
        "/",
        "/_next/static/chunks/main.js",
        "/_next/data/",
        "/api/",
        "/_next/build-manifest.json",
        "/_next/static/development/_devMiddlewareManifest.json",
        "/__nextjs_original-stack-frame",
    ],
    "Nuxt 3": [
        "/",
        "/_nuxt/builds/latest.json",
        "/_nuxt/builds/meta/",
        "/_payload.json",
    ],
    "Nuxt": [
        "/",
        "/_nuxt/",
    ],
    "Remix": [
        "/",
        "/build/_assets/",
        "/app/entry.client.tsx",
        "/__manifest",
    ],
    "Astro": [
        "/",
        "/_astro/",
        "/@vite/client",
        "/@id/",
    ],
    "Angular": [
        "/",
        "/ngsw.json",
        "/ngsw-worker.js",
        "/assets/config.json",
        "/sockjs-node/info",
    ],
    "SvelteKit": [
        "/",
        "/_app/",
        "/__data.json",
    ],
    "React": [
        "/",
        "/static/js/",
    ],
    "Vue": [
        "/",
        "/manifest.json",
    ],
    "CRA": [
        "/",
        "/asset-manifest.json",
    ],
    "Gatsby": [
        "/",
        "/page-data/",
        "/app-data.json",
    ],
    "Webpack (bundled)": [
        "/",
        "/webpack.runtime.js",
        "/manifest.json",
    ],
    "Vite": [
        "/",
        "/@vite/client",
    ],
}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class FrameworkHit:
    """One detected framework for a host."""

    framework: str
    host: str
    evidence: list[str] = field(default_factory=list)
    recommended_paths: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "framework": self.framework,
            "host": self.host,
            "evidence": list(self.evidence),
            "recommended_paths": list(self.recommended_paths),
        }


@dataclass
class FrameworkDetectionResult:
    """Aggregate of framework detections across all probed hosts."""

    hits: list[FrameworkHit] = field(default_factory=list)
    detected_frameworks: set[str] = field(default_factory=set)
    hosts_scanned: int = 0
    errors: int = 0
    extra_paths: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "hits": [h.to_dict() for h in self.hits],
            "detected_frameworks": sorted(self.detected_frameworks),
            "hosts_scanned": self.hosts_scanned,
            "errors": self.errors,
            "extra_path_count": len(self.extra_paths),
        }


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------


def detect_frameworks_from_content(
    html: str,
    js_bodies: Iterable[str] | None = None,
    *,
    host: str = "",
) -> list[FrameworkHit]:
    """Detect frameworks by inspecting already-fetched HTML + JS bodies.

    This is the cheap inner loop — no network I/O. The caller is
    responsible for providing the HTML and JS bodies; the orchestrator
    passes the bodies it already fetched during js_discovery.

    Args:
        html: HTML body of the index page.
        js_bodies: Iterable of JS bundle bodies already fetched for the
            host. Defaults to no extra JS inspection.
        host: Hostname (used only for the result metadata).

    Returns:
        One :class:`FrameworkHit` per detected framework, in the order
        they were detected. Each hit carries the evidence substrings
        that triggered detection and the framework's recommended URL
        probe list.
    """
    found: dict[str, FrameworkHit] = {}
    if html:
        for needle, framework in _HTML_JS_SIGNATURES:
            if needle in html and framework not in found:
                hit = FrameworkHit(
                    framework=framework,
                    host=host,
                    evidence=[needle],
                    recommended_paths=list(_FRAMEWORK_PROBES.get(framework, [])),
                )
                found[framework] = hit
    for js in js_bodies or ():
        if not js:
            continue
        for needle, framework in _HTML_JS_SIGNATURES:
            if needle in js and framework not in found:
                hit = FrameworkHit(
                    framework=framework,
                    host=host,
                    evidence=[needle],
                    recommended_paths=list(_FRAMEWORK_PROBES.get(framework, [])),
                )
                found[framework] = hit
    return list(found.values())


def _normalize_base(host: str) -> str:
    host = (host or "").strip().lower()
    if not host:
        return ""
    if "://" not in host:
        return f"https://{host}"
    return host


def probe_framework_endpoints(
    host: str,
    timeout_seconds: int = 6,
    max_response_bytes: int = 250_000,
) -> tuple[list[FrameworkHit], list[str]]:
    """Probe the host for the highest-value framework fingerprints.

    Issues a single GET against a handful of well-known SPA paths to
    confirm the framework (the cheap inner loop above can produce
    false positives from a stray comment, so we cross-check). Also
    returns the raw content of the most informative endpoint so the
    orchestrator can re-run :func:`detect_frameworks_from_content` on
    the actual SPA HTML.

    Args:
        host: Hostname to probe.
        timeout_seconds: Per-request timeout.
        max_response_bytes: Cap on response body size.

    Returns:
        Tuple of (framework_hits, raw_html_bodies). The raw HTML bodies
        are returned so the caller can run additional analysis without
        re-fetching the same endpoints.
    """
    base = _normalize_base(host)
    if not base or not is_safe_url(base):
        return [], []

    # Endpoints that, if 200, strongly imply the framework.
    high_value_probes = (
        "/_next/data/",
        "/ngsw.json",
        "/ngsw-worker.js",
        "/asset-manifest.json",
        "/manifest.json",
        "/_payload.json",
        "/__data.json",
    )

    raw_bodies: list[str] = []
    hits: dict[str, FrameworkHit] = {}

    for path in high_value_probes:
        url = urljoin(base + "/", path.lstrip("/"))
        body = _fetch_text_content(url, timeout_seconds, max_response_bytes)
        if not body:
            continue
        raw_bodies.append(body)
        # We treat any successful response as evidence and re-run the
        # cheap detector over the body to pull out the framework name.
        new_hits = detect_frameworks_from_content(body, host=host)
        for hit in new_hits:
            existing = hits.get(hit.framework)
            if existing is not None:
                existing.evidence.extend(hit.evidence)
            else:
                hit.evidence = list(dict.fromkeys(hit.evidence))
                hit.recommended_paths = list(_FRAMEWORK_PROBES.get(hit.framework, []))
                hits[hit.framework] = hit
        # Some probes are themselves the framework's manifest. Match on
        # path even if the body is too small to contain signatures.
        path_to_framework = {
            "/_next/data/": "Next.js",
            "/ngsw.json": "Angular",
            "/ngsw-worker.js": "Angular",
            "/asset-manifest.json": "CRA",
            "/manifest.json": "Vue",
            "/_payload.json": "Nuxt 3",
            "/__data.json": "SvelteKit",
        }
        for prefix, framework in path_to_framework.items():
            if path.startswith(prefix) and framework not in hits:
                hits[framework] = FrameworkHit(
                    framework=framework,
                    host=host,
                    evidence=[f"probed {path} -> 200"],
                    recommended_paths=list(_FRAMEWORK_PROBES.get(framework, [])),
                )

    return list(hits.values()), raw_bodies


def collect_recommended_paths(hits: Iterable[FrameworkHit]) -> list[str]:
    """Flatten the recommended_paths lists from a sequence of hits.

    Deduplicates while preserving insertion order, so operators can
    use the result as a deterministic URL seeding list.
    """
    seen: set[str] = set()
    ordered: list[str] = []
    for hit in hits:
        for path in hit.recommended_paths:
            if path and path not in seen:
                seen.add(path)
                ordered.append(path)
    return ordered


# ---------------------------------------------------------------------------
# Convenience: gather extra URLs from SPA-aware probes
# ---------------------------------------------------------------------------


def spa_aware_extra_urls(
    base_host: str,
    detected: list[FrameworkHit],
    *,
    timeout_seconds: int = 6,
    max_response_bytes: int = 250_000,
) -> set[str]:
    """Build the set of in-scope URLs the orchestrator should add to URL collection.

    For each detected framework we resolve its recommended paths
    against ``base_host`` and verify the URL is in scope. The result
    is a set of absolute URLs that downstream crawlers / Nuclei
    scanners can pick up.

    Args:
        base_host: Hostname to anchor the recommended paths to.
        detected: Per-host framework hits.
        timeout_seconds: Per-request timeout (currently unused, kept
            for forward-compatibility if we add live probing).
        max_response_bytes: Cap on response body size (currently unused).

    Returns:
        Set of absolute URLs (one per recommended path × host).
    """
    base = _normalize_base(base_host)
    if not base or not is_safe_url(base):
        return set()
    paths = collect_recommended_paths(detected)
    urls: set[str] = set()
    parsed = urlparse(base)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    for path in paths:
        if not path.startswith("/"):
            path = "/" + path
        url = origin.rstrip("/") + path
        if is_safe_url(url):
            urls.add(url)
    return urls


# ---------------------------------------------------------------------------
# Bundle manifest extraction
# ---------------------------------------------------------------------------


_BUNDLE_MANIFEST_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r'"([A-Za-z0-9_./-]+\.js)"', re.IGNORECASE), "js"),
    (re.compile(r'"([A-Za-z0-9_./-]+\.css)"', re.IGNORECASE), "css"),
    (re.compile(r'"([A-Za-z0-9_./-]+\.map)"', re.IGNORECASE), "map"),
)


def extract_bundle_manifest_entries(manifest_body: str) -> list[str]:
    """Pull asset entries out of a Webpack / Vite / CRA manifest body.

    The manifest is a JSON document mapping chunk names to asset paths.
    We extract every ``.js``, ``.css`` and ``.map`` path so the
    orchestrator can re-fetch them as additional JS bodies (where the
    actual route definitions / API clients live).
    """
    if not manifest_body:
        return []
    try:
        data = json.loads(manifest_body)
    except json.JSONDecodeError:
        return []
    entries: set[str] = set()
    if isinstance(data, dict):
        for value in data.values():
            if isinstance(value, str):
                entries.add(value)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, str):
                        entries.add(item)
            elif isinstance(value, dict):
                # Webpack 5 stats: assetsByChunkName
                for sub_value in value.values():
                    if isinstance(sub_value, str):
                        entries.add(sub_value)
                    elif isinstance(sub_value, list):
                        for item in sub_value:
                            if isinstance(item, str):
                                entries.add(item)
    return sorted(entries)


__all__ = [
    "FrameworkDetectionResult",
    "FrameworkHit",
    "collect_recommended_paths",
    "detect_frameworks_from_content",
    "extract_bundle_manifest_entries",
    "probe_framework_endpoints",
    "spa_aware_extra_urls",
]
