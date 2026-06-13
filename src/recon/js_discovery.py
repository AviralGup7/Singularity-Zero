"""JS endpoint discovery helpers extracted from urls.py.

This module contains the logic for fetching HTML/JS, extracting
script references and candidate endpoints, and running discovery across
hosts in parallel. It mirrors the behaviour previously embedded in
`src.recon.urls` but keeps the surface small for easier testing and
reuse.
"""

from __future__ import annotations

import logging
import re
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from typing import Any
from urllib.parse import urljoin

from src.core.models import Config
from src.recon.collectors.observability import emit_collection_progress
from src.recon.js_fetcher import _fetch_text_content
from src.recon.js_parsers import (
    _extract_js_candidate_urls,
    _extract_script_urls_from_html,
    _normalized_scope_roots,
)
from src.recon.js_parsers_v2 import (
    analyze_service_worker,
    analyze_wasm_url,
    discover_and_analyze_manifest,
    extract_endpoints_v2,
    extract_source_map_url,
    extract_tokens_and_keys,
    follow_source_map_chain,
    is_source_map_body,
)
from src.recon.url_validation import is_safe_url

logger = logging.getLogger(__name__)


def _load_secret_patterns(config_path: str | None = None) -> list[tuple[re.Pattern[str], str]]:
    """Load secret regex patterns from a JSON file if configured/exists, falling back to static list."""
    import json
    from pathlib import Path

    path = None
    if config_path:
        path = Path(config_path)
    else:
        resolved_default = Path(__file__).resolve().parent / "configs" / "secret_patterns.json"
        if resolved_default.exists():
            path = resolved_default

    if path and path.exists():
        try:
            with path.open("r", encoding="utf-8") as f:
                patterns_data = json.load(f)
                if isinstance(patterns_data, list):
                    compiled = []
                    for item in patterns_data:
                        pat_str = item.get("pattern")
                        label = item.get("label")
                        if pat_str and label:
                            flags = re.IGNORECASE if item.get("ignore_case", True) else 0
                            compiled.append((re.compile(pat_str, flags), label))
                    return compiled
        except Exception as exc:
            logger.warning("Failed to load secret patterns from %s: %s", path, exc)

    return _STATIC_SECRET_PATTERNS


_STATIC_SECRET_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(
            r"(?:api_key|apikey|access_token|secret_key|secretToken)[\"']?\s*[:=]\s*[\"']([a-zA-Z0-9_\-]{20,})[\"']",
            re.IGNORECASE,
        ),
        "Generic API Key/Token",
    ),
    (re.compile(r"AKIA[0-9A-Z]{16}", re.IGNORECASE), "AWS Access Key ID"),
    (re.compile(r"sk-[a-zA-Z0-9]{48}", re.IGNORECASE), "OpenAI API Key"),
    (re.compile(r"Bearer\s+([a-zA-Z0-9_\-\.]{20,})", re.IGNORECASE), "Bearer Token"),
    (re.compile(r"gh[po]_[a-zA-Z0-9]{36}", re.IGNORECASE), "GitHub Token"),
    (re.compile(r"xox[baprs]-[a-zA-Z0-9\-]{10,}", re.IGNORECASE), "Slack Token"),
]

_SECRET_PATTERNS = _load_secret_patterns()


def _extract_secrets(
    content: str,
    *,
    redact_prefix_len: int = 4,
    expose_full: bool = False,
) -> list[dict[str, str]]:
    """Extract secret-shaped strings from JS content with safe redaction."""
    if redact_prefix_len < 0 or redact_prefix_len > 32:
        redact_prefix_len = 4
    secrets = []
    for pattern, label in _SECRET_PATTERNS:
        for match in pattern.finditer(content):
            val = match.group(1) if match.groups() else match.group(0)
            if expose_full:
                secrets.append({"type": label, "value": val})
            else:
                if len(val) <= redact_prefix_len + 4:
                    redacted = "*" * len(val)
                else:
                    head = val[:redact_prefix_len]
                    tail = val[-4:]
                    redacted = f"{head}…{tail}"
                secrets.append({"type": label, "value": redacted})
    return secrets


def _collect_js_discovery_urls(
    live_hosts: set[str],
    scope_entries: list[str],
    config: Config,
    progress_callback: Any = None,
    runtime_budget_seconds: int | None = None,
) -> tuple[set[str], dict[str, Any]]:
    filters = config.filters or {}
    if not bool(filters.get("js_discovery_enabled", True)):
        return set(), {"status": "disabled", "duration_seconds": 0.0, "new_urls": 0}

    max_hosts = max(1, int(filters.get("js_discovery_max_hosts", 25) or 25))
    workers = max(1, int(filters.get("js_discovery_workers", 8) or 8))
    timeout_seconds = max(2, int(filters.get("js_discovery_timeout_seconds", 8) or 8))
    max_js_files_per_host = max(
        1,
        int(filters.get("js_discovery_max_js_files_per_host", 12) or 12),
    )
    max_discovered_urls = max(
        50,
        int(filters.get("js_discovery_max_urls", 2000) or 2000),
    )
    max_response_bytes = max(
        4096,
        int(filters.get("js_discovery_max_response_bytes", 250000) or 250000),
    )
    js_discovery_time_budget_seconds = max(
        1,
        int(filters.get("js_discovery_time_budget_seconds", 180) or 180),
    )
    if runtime_budget_seconds is not None:
        js_discovery_time_budget_seconds = max(
            1,
            min(js_discovery_time_budget_seconds, int(runtime_budget_seconds)),
        )

    scoped_hosts = sorted({host for host in live_hosts if host})[:max_hosts]
    if not scoped_hosts:
        return set(), {"status": "skipped", "duration_seconds": 0.0, "new_urls": 0}

    scope_roots = _normalized_scope_roots(scope_entries)
    started = time.monotonic()
    discovered_urls: set[str] = set()
    all_secrets: list[dict[str, Any]] = []
    endpoint_provenance: dict[str, str] = {}
    wasm_results: list[dict[str, Any]] = []
    sw_results: list[dict[str, Any]] = []
    manifest_results: list[dict[str, Any]] = []
    wasm_attack_surface: list[str] = []
    sw_attack_surface: list[dict[str, Any]] = []
    hosts_scanned = 0
    script_refs = 0
    js_files_fetched = 0
    errors = 0
    budget_exceeded = False

    def _scan_single_host(
        base_url: str,
    ) -> tuple[
        set[str],
        int,
        int,
        list[dict[str, Any]],
        dict[str, Any],
        list[dict[str, Any]],
        list[dict[str, Any]],
        list[dict[str, Any]],
    ]:
        host_discovered: set[str] = set()
        host_secrets: list[dict[str, Any]] = []
        host_wasm: list[dict[str, Any]] = []
        host_sw: list[dict[str, Any]] = []
        host_manifest: list[dict[str, Any]] = []
        host_provenance: dict[str, str] = {}
        html = _fetch_text_content(base_url, timeout_seconds, max_response_bytes)
        if not html:
            return (
                host_discovered,
                0,
                0,
                host_secrets,
                host_provenance,
                host_wasm,
                host_sw,
                host_manifest,
            )

        host_discovered.update(extract_endpoints_v2(html, base_url, scope_roots))
        host_discovered.update(_extract_js_candidate_urls(html, base_url, scope_roots))
        for ep in host_discovered:
            host_provenance[ep] = base_url
        manifest_info = discover_and_analyze_manifest(base_url, scope_roots, html_body=html)
        if manifest_info.get("discovered"):
            host_manifest.append(manifest_info)
        script_urls = sorted(_extract_script_urls_from_html(html, base_url, scope_roots))
        fetched = 0
        for js_url in script_urls[:max_js_files_per_host]:
            js_body = _fetch_text_content(js_url, timeout_seconds, max_response_bytes)
            if not js_body:
                continue
            fetched += 1
            js_endpoints = extract_endpoints_v2(js_body, js_url, scope_roots)
            js_candidates = _extract_js_candidate_urls(js_body, js_url, scope_roots)
            host_discovered.update(js_endpoints)
            host_discovered.update(js_candidates)
            for ep in js_endpoints:
                host_provenance[ep] = js_url
            for ep in js_candidates:
                host_provenance[ep] = js_url
            extracted_secrets = _extract_secrets(js_body, redact_prefix_len=4)
            extracted_secrets.extend(extract_tokens_and_keys(js_body))
            for secret in extracted_secrets:
                host_secrets.append(
                    {"url": js_url, "type": secret["type"], "value": secret["value"]}
                )
            if re.search(r"navigator\.serviceWorker|serviceWorker\.register", js_body):
                sw_candidate = re.search(r'["\']([^"\']+\.js)["\']', js_body)
                if sw_candidate:
                    sw_url = sw_candidate.group(1)
                    if not sw_url.startswith(("http://", "https://")):
                        sw_url = urljoin(js_url, sw_url)
                    if is_safe_url(sw_url):
                        sw_info = analyze_service_worker(sw_url, base_url, scope_roots)
                        host_sw.append(sw_info)
                        if sw_info.get("fetch_routes") or sw_info.get("cache_names"):
                            sw_attack_surface.append(sw_info)
                sw_url = urljoin(js_url, "sw.js")
                if is_safe_url(sw_url):
                    sw_info = analyze_service_worker(sw_url, base_url, scope_roots)
                    if sw_info.get("fetch_routes") or sw_info.get("cache_names"):
                        host_sw.append(sw_info)
                        sw_attack_surface.append(sw_info)
            for m in re.finditer(r"""\.wasm\s*["']([^"']+)["']""", js_body):
                wasm_candidate = m.group(1)
                if not wasm_candidate.startswith(("http://", "https://")):
                    wasm_candidate = urljoin(js_url, wasm_candidate)
                if is_safe_url(wasm_candidate):
                    w_disc, w_strings = analyze_wasm_url(wasm_candidate, base_url, scope_roots)
                    if w_disc or w_strings:
                        host_wasm.append(
                            {
                                "url": wasm_candidate,
                                "discovered": sorted(w_disc),
                                "strings": w_strings[:20],
                            }
                        )
                        wasm_attack_surface.extend(sorted(w_disc))
            for m in re.finditer(r"""\.wasm\b""", js_body):
                # Extract the URL prefix before .wasm extension
                start = max(0, m.start() - 100)
                context = js_body[start:m.end()]
                # Look for quoted path ending in .wasm
                url_match = re.search(r"""['"]([^'"]*\.wasm)['"]""", context)
                if url_match:
                    wasm_path = url_match.group(1)
                    full_url = urljoin(js_url, wasm_path) if not wasm_path.startswith(('http://', 'https://')) else wasm_path
                    if _in_scope(full_url, scope_roots):
                        w_disc.add(full_url)
            source_map_candidates: list[str] = [js_url + ".map"]
            declared_map = extract_source_map_url(js_body)
            if declared_map:
                source_map_candidates.append(urljoin(js_url, declared_map))
            for map_url in dict.fromkeys(source_map_candidates):
                map_body = _fetch_text_content(map_url, timeout_seconds, max_response_bytes)
                if not map_body:
                    continue
                host_discovered.add(map_url)
                if is_source_map_body(map_body):
                    chain_disc, chain_prov = follow_source_map_chain(
                        map_url, map_body, base_url, scope_roots
                    )
                    host_discovered.update(chain_disc)
                    host_provenance.update(chain_prov)
                else:
                    map_endpoints = extract_endpoints_v2(map_body, map_url, scope_roots)
                    host_discovered.update(map_endpoints)
                    for ep in map_endpoints:
                        host_provenance[ep] = map_url
                fetched += 1

        host_discovered.update(script_urls[:max_js_files_per_host])
        return (
            host_discovered,
            len(script_urls),
            fetched,
            host_secrets,
            host_provenance,
            host_wasm,
            host_sw,
            host_manifest,
        )

    emit_collection_progress(
        progress_callback,
        f"Running JS endpoint discovery across {len(scoped_hosts)} hosts",
        65,
    )
    max_workers = min(workers, len(scoped_hosts))
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        pending: dict[Any, str] = {}
        submitted = 0

        while submitted < len(scoped_hosts) and len(pending) < max_workers:
            host = scoped_hosts[submitted]
            pending[executor.submit(_scan_single_host, host)] = host
            submitted += 1

        while pending:
            elapsed = time.monotonic() - started
            if elapsed >= js_discovery_time_budget_seconds:
                budget_exceeded = True
                for future in pending:
                    future.cancel()
                emit_collection_progress(
                    progress_callback,
                    (
                        "JS endpoint discovery budget exceeded "
                        f"({elapsed:.1f}s/{js_discovery_time_budget_seconds}s); "
                        "continuing with discovered URLs so far"
                    ),
                    66,
                    processed=hosts_scanned,
                    total=len(scoped_hosts),
                    stage_percent=int((hosts_scanned / max(1, len(scoped_hosts))) * 100),
                )
                break

            done, _ = wait(list(pending), timeout=0.2, return_when=FIRST_COMPLETED)
            if not done:
                continue

            for future in done:
                pending.pop(future, None)
                try:
                    (
                        host_urls,
                        host_script_refs,
                        host_js_files,
                        h_secrets,
                        h_prov,
                        h_wasm,
                        h_sw,
                        h_manifest,
                    ) = future.result()
                    all_secrets.extend(h_secrets)
                    endpoint_provenance.update(h_prov)
                    wasm_results.extend(h_wasm)
                    sw_results.extend(h_sw)
                    manifest_results.extend(h_manifest)
                except Exception as exc:
                    logger.warning("JS discovery scan failed for host: %s", exc, exc_info=True)
                    host_urls, host_script_refs, host_js_files = set(), 0, 0
                    errors += 1
                hosts_scanned += 1
                script_refs += host_script_refs
                js_files_fetched += host_js_files
                before = len(discovered_urls)
                discovered_urls.update(host_urls)
                if max_discovered_urls > 0 and len(discovered_urls) > max_discovered_urls:
                    prioritized = sorted(discovered_urls, key=lambda item: ("?" in item, item))
                    discovered_urls = set(prioritized[:max_discovered_urls])
                emit_collection_progress(
                    progress_callback,
                    (
                        f"js discovery host {hosts_scanned}/{len(scoped_hosts)}: "
                        f"+{max(0, len(discovered_urls) - before)} URLs, total {len(discovered_urls)}"
                    ),
                    66,
                    processed=hosts_scanned,
                    total=len(scoped_hosts),
                    stage_percent=int((hosts_scanned / max(1, len(scoped_hosts))) * 100),
                )

                if submitted >= len(scoped_hosts):
                    continue
                if time.monotonic() - started >= js_discovery_time_budget_seconds:
                    continue

                host = scoped_hosts[submitted]
                pending[executor.submit(_scan_single_host, host)] = host
                submitted += 1

    meta = {
        "status": "degraded_timeout" if budget_exceeded else ("ok" if discovered_urls else "empty"),
        "duration_seconds": round(time.monotonic() - started, 1),
        "new_urls": len(discovered_urls),
        "hosts_scanned": hosts_scanned,
        "script_refs": script_refs,
        "js_files_fetched": js_files_fetched,
        "errors": errors,
        "js_discovery_time_budget_seconds": js_discovery_time_budget_seconds,
        "budget_exceeded": budget_exceeded,
        "js_secrets_found": all_secrets,
        "endpoint_provenance": endpoint_provenance,
        "wasm_findings": wasm_results,
        "wasm_attack_surface": wasm_attack_surface,
        "service_workers": sw_results,
        "sw_attack_surface": sw_attack_surface,
        "pwa_manifests": manifest_results,
    }
    return discovered_urls, meta


__all__ = ["_collect_js_discovery_urls"]
