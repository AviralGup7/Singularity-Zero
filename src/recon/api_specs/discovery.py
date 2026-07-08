"""API spec discovery: URL candidate generation, probing, and orchestration."""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Iterable
from functools import partial
from typing import Any
from urllib.parse import urljoin, urlparse

import requests

from src.infrastructure.execution_engine.shared_pool import get_recon_executor
from src.recon.api_specs.grpc import (
    DEFAULT_GRPC_PATHS,
    DEFAULT_GRPC_WEB_PATHS,
    DEFAULT_PROTO_PATHS,
)
from src.recon.api_specs.openapi import (
    DEFAULT_ASYNCAPI_PATHS,
    DEFAULT_AVRO_PATHS,
    DEFAULT_GRAPHQL_SDL_PATHS,
    DEFAULT_SPEC_PATHS,
    DEFAULT_THRIFT_PATHS,
    SpecEndpoint,
    _expand_server_variables,
)
from src.recon.api_specs.parsers import _parse_spec_body_enhanced
from src.recon.url_validation import is_safe_url

logger = logging.getLogger(__name__)

# Concurrently in-flight spec probes.
_PROBE_CONCURRENCY = 6

# Per-probe timeout in seconds.
_PROBE_TIMEOUT_SECONDS = 6

_JS_AUTH_RE = re.compile(
    r"(?i)(bearer\s+[a-za-z0-9_\-.]+|api[_-]?key\s*[=:]\s*['\"]?[a-za-z0-9_\-]+['\"]?|authorization:\s*bearer\s+[a-za-z0-9_\-.]+|x-api-key:\s*['\"]?[a-za-z0-9_\-]+['\"]?)"
)


def extract_auth_headers_from_js_parsers(
    js_parsers_result: dict[str, Any] | None,
) -> dict[str, str]:
    auth_headers: dict[str, str] = {}
    if not isinstance(js_parsers_result, dict):
        return auth_headers

    def _walk(node: Any) -> None:
        if isinstance(node, dict):
            for key, val in node.items():
                k = str(key).lower()
                if k in {"authorization", "x-api-key", "api-key", "bearer", "auth"} and isinstance(
                    val, str
                ):
                    auth_headers[k] = val
                elif isinstance(val, (dict, list)):
                    _walk(val)
        elif isinstance(node, list):
            for item in node:
                _walk(item)

    _walk(js_parsers_result)
    text_blob = json.dumps(js_parsers_result)
    for m in _JS_AUTH_RE.finditer(text_blob):
        token = m.group(1).strip()
        if token.startswith("bearer ") or token.startswith("Bearer "):
            auth_headers["authorization"] = token
        elif "api-key" in token.lower() or "apikey" in token.lower():
            auth_headers["x-api-key"] = token.split(":")[-1].strip().strip("\"'")
    return auth_headers


# ---------------------------------------------------------------------------
# Enhanced URL candidate generation
# ---------------------------------------------------------------------------


def _candidate_spec_urls_enhanced(
    host: str,
    extra_paths: Iterable[str] | None = None,
    include_asyncapi: bool = True,
    include_graphql_sdl: bool = True,
    include_proto: bool = True,
    include_grpc_web: bool = True,
    include_thrift: bool = True,
    include_avro: bool = True,
    server_variable_overrides: dict[str, list[str]] | None = None,
    include_grpc_paths: bool = True,
) -> list[str]:
    base = _normalize_base(host)
    if not base or not is_safe_url(base):
        return []
    parsed = urlparse(base)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    paths: list[str] = []
    paths.extend(DEFAULT_SPEC_PATHS)
    if include_asyncapi:
        paths.extend(DEFAULT_ASYNCAPI_PATHS)
    if include_graphql_sdl:
        paths.extend(DEFAULT_GRAPHQL_SDL_PATHS)
    if include_proto:
        paths.extend(DEFAULT_PROTO_PATHS)
    if include_grpc_web:
        paths.extend(DEFAULT_GRPC_WEB_PATHS)
    if include_thrift:
        paths.extend(DEFAULT_THRIFT_PATHS)
    if include_avro:
        paths.extend(DEFAULT_AVRO_PATHS)
    if include_grpc_paths:
        paths.extend(DEFAULT_GRPC_PATHS)
    if extra_paths:
        paths.extend(p for p in extra_paths if p)

    urls: list[str] = []
    seen: set[str] = set()
    for path in paths:
        if not path.startswith("/"):
            path = "/" + path
        raw_url = urljoin(origin.rstrip("/") + "/", path.lstrip("/"))
        if raw_url in seen:
            continue
        seen.add(raw_url)
        if not is_safe_url(raw_url):
            continue
        for expanded in _expand_server_variables(raw_url, server_variable_overrides):
            if expanded not in seen:
                seen.add(expanded)
                urls.append(expanded)
    return urls


# ---------------------------------------------------------------------------
# Auth-aware probing
# ---------------------------------------------------------------------------


def _probe_spec_url_with_auth(
    url: str,
    *,
    timeout_seconds: int = _PROBE_TIMEOUT_SECONDS,
    auth_headers: dict[str, str] | None = None,
) -> SpecEndpoint | None:
    host = (urlparse(url).hostname or "").lower()
    req_headers = {"User-Agent": "cyber-pipeline/2.0 (api-spec-probe)"}
    if isinstance(auth_headers, dict):
        req_headers.update({k: str(v) for k, v in auth_headers.items() if v})
    try:
        resp = requests.get(  # nosec
            url,
            timeout=max(2, timeout_seconds),
            allow_redirects=True,
            headers=req_headers,
        )
    except requests.RequestException as exc:
        logger.debug("Spec probe failed for %s: %s", url, exc)
        return None
    if resp.status_code != 200:
        return None
    body = resp.text or ""
    content_type = resp.headers.get("content-type", "")
    parsed = _parse_spec_body_enhanced(body, content_type)
    if not parsed:
        return None
    kind, spec = parsed
    return SpecEndpoint(
        host=host,
        url=url,
        status_code=resp.status_code,
        content_type=content_type,
        spec_kind=kind,
        spec=spec,
    )


# ---------------------------------------------------------------------------
# Probing
# ---------------------------------------------------------------------------


def _normalize_base(host: str) -> str:
    host = (host or "").strip().lower()
    if not host:
        return ""
    if "://" in host:
        return host
    return f"https://{host}"


def _candidate_spec_urls(
    host: str,
    extra_paths: Iterable[str] | None,
) -> list[str]:
    base = _normalize_base(host)
    if not base or not is_safe_url(base):
        return []
    origin = f"{urlparse(base).scheme}://{urlparse(base).netloc}"
    paths = list(DEFAULT_SPEC_PATHS)
    if extra_paths:
        paths.extend(p for p in extra_paths if p)
    urls: list[str] = []
    seen: set[str] = set()
    for path in paths:
        if not path.startswith("/"):
            path = "/" + path
        url = urljoin(origin.rstrip("/") + "/", path.lstrip("/"))
        if url in seen:
            continue
        seen.add(url)
        if is_safe_url(url):
            urls.append(url)
    return urls


def _probe_spec_url(url: str, *, timeout_seconds: int) -> SpecEndpoint | None:
    host = (urlparse(url).hostname or "").lower()
    try:
        resp = requests.get(  # nosec
            url,
            timeout=max(2, timeout_seconds),
            allow_redirects=True,
            headers={"User-Agent": "cyber-pipeline/2.0 (api-spec-probe)"},
        )
    except requests.RequestException as exc:
        logger.debug("Spec probe failed for %s: %s", url, exc)
        return None
    if resp.status_code != 200:
        return None
    body = resp.text or ""
    content_type = resp.headers.get("content-type", "")
    parsed = _parse_spec_body_enhanced(body, content_type)
    if not parsed:
        return None
    kind, spec = parsed
    return SpecEndpoint(
        host=host,
        url=url,
        status_code=resp.status_code,
        content_type=content_type,
        spec_kind=kind,
        spec=spec,
    )


def discover_api_specs(
    hosts: Iterable[str],
    *,
    extra_paths: Iterable[str] | None = None,
    max_workers: int = _PROBE_CONCURRENCY,
    timeout_seconds: int = _PROBE_TIMEOUT_SECONDS,
    auth_headers: dict[str, str] | None = None,
    js_parsers_v2_results: dict[str, Any] | None = None,
    enhanced: bool = True,
    server_variable_overrides: dict[str, list[str]] | None = None,
) -> list[SpecEndpoint]:
    """Discover API spec endpoints across a set of hosts.

    Args:
        hosts: Hostnames or base URLs to probe.
        extra_paths: Additional relative paths to test.
        max_workers: Max concurrent probes.
        timeout_seconds: Per-probe timeout.
        auth_headers: Optional HTTP headers to send with each probe.
        js_parsers_v2_results: Optional results from js_parsers_v2; auth
            headers are extracted automatically and merged with ``auth_headers``.
        enhanced: Use enhanced path lists (AsyncAPI, gRPC, Thrift, Avro, etc.).
        server_variable_overrides: Override DEFAULT_SERVER_VARIABLES if needed.

    Returns:
        List of :class:`SpecEndpoint` for every URL that returned a
        recognisable API spec. Endpoints that returned 200 with a
        non-spec body are silently dropped.
    """
    merged_auth: dict[str, str] = {}
    if isinstance(auth_headers, dict):
        merged_auth.update(auth_headers)
    if isinstance(js_parsers_v2_results, dict):
        extracted = extract_auth_headers_from_js_parsers(js_parsers_v2_results)
        merged_auth.update(extracted)

    _probe = (
        _probe_spec_url_with_auth
        if (merged_auth or (enhanced and server_variable_overrides))
        else _probe_spec_url
    )

    candidate_urls: list[str] = []
    for host in hosts:
        if enhanced:
            candidate_urls.extend(
                _candidate_spec_urls_enhanced(
                    host,
                    extra_paths,
                    server_variable_overrides=server_variable_overrides,
                )
            )
        else:
            candidate_urls.extend(_candidate_spec_urls(host, extra_paths))
    if not candidate_urls:
        return []

    results: list[SpecEndpoint] = []
    executor = get_recon_executor()
    futures = []
    for url in candidate_urls:
        _probe_fn = (
            partial(
                _probe_spec_url_with_auth,
                auth_headers=merged_auth,
            )
            if _probe is _probe_spec_url_with_auth
            else _probe
        )
        futures.append(
            executor.submit(
                _probe_fn,
                url,
                timeout_seconds=timeout_seconds,
            )
        )
    for fut in futures:
        try:
            endpoint = fut.result()
        except Exception as exc:  # noqa: BLE001
            logger.debug("Spec probe future failed: %s", exc)
            continue
        if endpoint is not None:
            results.append(endpoint)
    return results
