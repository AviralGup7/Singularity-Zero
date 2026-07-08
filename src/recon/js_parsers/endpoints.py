"""Higher-level endpoint analysis functions."""

from __future__ import annotations

import json
import logging
import re
import string
from typing import Any
from urllib.parse import urljoin, urlparse

import requests

from src.recon.js_fetcher import _fetch_text_content
from src.recon.js_parsers.regex_extractors import (
    _MINIFIED_EXT_RE,
    _NODE_MODULES_SEG,
)
from src.recon.url_validation import is_safe_url

logger = logging.getLogger(__name__)


def _is_in_scope_url(url: str, scope_roots: set[str]) -> bool:
    """Check if URL hostname matches any scope root or subdomain thereof."""
    if not scope_roots:
        return True
    hostname = (urlparse(url).hostname or "").strip().lower()
    if not hostname:
        return False
    return any(hostname == root or hostname.endswith(f".{root}") for root in scope_roots)


def _is_minified_or_node_modules(url: str) -> bool:
    if _NODE_MODULES_SEG.search(url or ""):
        return True
    if _MINIFIED_EXT_RE.search(url or ""):
        return True
    return False


def analyze_wasm_url(
    wasm_url: str,
    base_url: str,
    scope_roots: set[str],
    max_bytes: int = 50000,
) -> tuple[set[str], list[str]]:
    wasm_discovered: set[str] = set()
    wasm_strings: list[str] = []
    if not (wasm_url or "").endswith(".wasm"):
        return wasm_discovered, wasm_strings
    hostname = (urlparse(wasm_url).hostname or "").lower()
    if scope_roots and not any(hostname == r or hostname.endswith("." + r) for r in scope_roots):
        return wasm_discovered, wasm_strings
    try:
        resp = requests.get(
            wasm_url,
            timeout=8,
            allow_redirects=False,
            headers={"User-Agent": "target-specific-pipeline/2.0"},
        )
        if resp.status_code >= 400:
            return wasm_discovered, wasm_strings
        data = resp.content[:max_bytes]
    except requests.RequestException:
        return wasm_discovered, wasm_strings
    ascii_chars = set(string.printable)
    current: list[str] = []
    for byte in data:
        ch = chr(byte)
        if ch in ascii_chars and ch != "\x00":
            current.append(ch)
        else:
            if len(current) >= 6:
                s = "".join(current)
                wasm_strings.append(s)
                for url in re.findall(r"(https?://[^\s\"'<>]+)", s):
                    wasm_discovered.add(url)
                for path in re.findall(r"(/[A-Za-z0-9_/\-]{3,}(?:\?[^\s\"'<>]*)?)", s):
                    wasm_discovered.add(urljoin(base_url, path))
            current = []
    return wasm_discovered, wasm_strings


def analyze_service_worker(
    sw_url: str,
    base_url: str,
    scope_roots: set[str],
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "sw_url": sw_url,
        "cache_names": [],
        "fetch_routes": [],
        "sync_endpoints": [],
        "push_endpoints": [],
        "wasm_references": [],
    }
    body = _fetch_text_content(sw_url, 8, 250_000)
    if not body:
        return result
    for match in re.finditer(r'["\']([^"\']+\.wasm)["\']', body):
        wasm_url = match.group(1)
        resolved = urljoin(sw_url, wasm_url)
        if is_safe_url(resolved):
            result["wasm_references"].append(resolved)
    for name_match in re.finditer(r'cacheName\s*[:=]\s*["\']([^"\']+)["\']', body):
        result["cache_names"].append(name_match.group(1))
    route_patterns = re.findall(
        r"""(?:event\.request|fetch\(\s*)(['"`])([^'"`]+)\1""",
        body,
    )
    for _, route in route_patterns:
        if route and not route.startswith(("javascript:", "data:")):
            result["fetch_routes"].append(route)
    for push_match in re.finditer(r'push\.subscribe\s*\(\s*["\']([^"\']+)["\']', body):
        result["push_endpoints"].append(push_match.group(1))
    for sync_match in re.finditer(r'sync\.register\s*\(\s*["\']([^"\']+)["\']', body):
        result["sync_endpoints"].append(sync_match.group(1))
    return result


def discover_and_analyze_manifest(
    base_url: str,
    scope_roots: set[str],
    html_body: str | None = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "manifest_url": None,
        "discovered": False,
        "start_url": None,
        "scope": None,
        "related_applications": [],
        "shortcuts": [],
        "external_start_url": False,
        "warnings": [],
        "raw": None,
    }
    candidates: list[str] = []
    if html_body:
        for match in re.finditer(
            r'<link[^>]+rel\s*=\s*["\'][^"\']*manifest[^"\']*["\'][^>]+href\s*=\s*["\']([^"\']+)["\']',
            html_body,
            re.IGNORECASE,
        ):
            candidates.append(match.group(1))
    candidates.append(base_url.rstrip("/") + "/manifest.json")
    seen: set[str] = set()
    for candidate in candidates:
        absolute = (
            candidate
            if candidate.startswith(("http://", "https://"))
            else urljoin(base_url, candidate)
        )
        if absolute in seen:
            continue
        seen.add(absolute)
        if not is_safe_url(absolute):
            continue
        body = _fetch_text_content(absolute, 6, 250_000)
        if not body:
            continue
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            continue
        result["manifest_url"] = absolute
        result["discovered"] = True
        result["raw"] = data
        result["start_url"] = data.get("start_url")
        result["scope"] = data.get("scope")
        result["related_applications"] = data.get("related_applications", []) or []
        result["shortcuts"] = data.get("shortcuts", []) or []
        if result["start_url"]:
            if result["start_url"].startswith("http://") or result["start_url"].startswith(
                "https://"
            ):
                start_netloc = urlparse(result["start_url"]).netloc.lower()
                base_netloc = urlparse(base_url).netloc.lower()
                if start_netloc != base_netloc:
                    result["external_start_url"] = True
                    result["warnings"].append(
                        f"start_url {result['start_url']} is on a different origin"
                    )
        break
    return result
