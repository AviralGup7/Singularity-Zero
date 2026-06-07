"""OpenAPI / Swagger / GraphQL introspection discovery.

Modern APIs almost always publish a machine-readable schema:

* REST APIs: ``/openapi.json``, ``/openapi.yaml``, ``/swagger.json``,
  ``/v1/api-docs``, ``/v2/api-docs``, ``/v3/api-docs``,
  ``/swagger-resources``, ``/api/swagger``, ``/api/openapi``, etc.
* GraphQL: see :mod:`src.recon.graphql_introspection`.
* gRPC: reflection endpoint, plus ``.proto`` files occasionally exposed
  by misconfigured static-file servers.
* Postman: ``/postman.json``, ``/api.postman_collection.json``.

When these endpoints are accessible, they are a goldmine: every
operation, every parameter, every authentication scheme is right there
in machine-readable form. The previous ``api_reconstructor`` only
*guessed* operations from URL paths, missing request bodies, response
schemas, and the authoritative operation names.

This module probes the most common spec locations and, on a 200
response, parses the spec and merges it into a single OpenAPI 3.0
document. The resulting structure is what the rest of the recon
pipeline should consume as the canonical API surface.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor
from typing import Any
from urllib.parse import urljoin, urlparse

import requests

from src.recon.url_validation import is_safe_url

logger = logging.getLogger(__name__)

# Default OpenAPI / Swagger discovery paths, in priority order. The
# list is intentionally short to keep the scan fast; operators with a
# known custom path can supply it via the ``api_spec_extra_paths`` config.
DEFAULT_SPEC_PATHS: tuple[str, ...] = (
    "/openapi.json",
    "/openapi.yaml",
    "/openapi.yml",
    "/swagger.json",
    "/swagger.yaml",
    "/swagger.yml",
    "/v1/api-docs",
    "/v2/api-docs",
    "/v3/api-docs",
    "/api-docs",
    "/api/openapi.json",
    "/api/openapi.yaml",
    "/api/swagger.json",
    "/api/swagger.yaml",
    "/api/docs",
    "/docs/openapi.json",
    "/docs/openapi.yaml",
    "/docs/swagger.json",
    "/swagger-resources",
    "/swagger/v1/swagger.json",
    "/swagger/v2/swagger.json",
    "/_swagger.json",
    "/postman.json",
    "/api.postman_collection.json",
)

# gRPC reflection hints — we cannot actually invoke a gRPC reflection
# request from a plain HTTP client, but we can probe the canonical
# well-known HTTP paths that some gateways expose.
DEFAULT_GRPC_PATHS: tuple[str, ...] = (
    "/grpc.reflection.v1.ServerReflection",
    "/grpc.reflection.v1alpha.ServerReflection",
    "/grpc.health.v1.Health",
)

# Concurrently in-flight spec probes.
_PROBE_CONCURRENCY = 6

# Per-probe timeout in seconds.
_PROBE_TIMEOUT_SECONDS = 6


# ---------------------------------------------------------------------------
# Public data class
# ---------------------------------------------------------------------------


class SpecEndpoint:
    """One discovered API spec endpoint."""

    __slots__ = (
        "host",
        "url",
        "status_code",
        "content_type",
        "spec_kind",
        "spec",
    )

    def __init__(
        self,
        host: str,
        url: str,
        status_code: int,
        content_type: str,
        spec_kind: str,
        spec: Any,
    ) -> None:
        self.host = host
        self.url = url
        self.status_code = status_code
        self.content_type = content_type
        self.spec_kind = spec_kind
        self.spec = spec

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "url": self.url,
            "status_code": self.status_code,
            "content_type": self.content_type,
            "spec_kind": self.spec_kind,
            "operation_count": self._count_operations(),
        }

    def _count_operations(self) -> int:
        if not isinstance(self.spec, dict):
            return 0
        paths = self.spec.get("paths")
        if not isinstance(paths, dict):
            return 0
        total = 0
        for path_item in paths.values():
            if isinstance(path_item, dict):
                total += sum(
                    1 for k in path_item if k.lower() in {"get", "post", "put", "patch", "delete", "head", "options", "trace"}
                )
        return total


# ---------------------------------------------------------------------------
# Spec parsing
# ---------------------------------------------------------------------------


def _looks_like_openapi(text: str) -> bool:
    """Cheap heuristic: does the body look like a Swagger / OpenAPI document?"""
    if not text:
        return False
    stripped = text.lstrip()
    if stripped.startswith("{"):
        return '"swagger"' in stripped[:1024] or '"openapi"' in stripped[:1024]
    if stripped.startswith("---") or stripped.startswith("openapi:") or stripped.startswith("swagger:"):
        return True
    return False


def _parse_spec_body(text: str, content_type: str) -> tuple[str, Any] | None:
    """Return (kind, parsed_spec) or None when the body is not a recognised spec.

    ``kind`` is one of ``"openapi-3"``, ``"swagger-2"``, ``"postman"``,
    ``"unknown-json"``.
    """
    if not text:
        return None
    ct = (content_type or "").lower()
    stripped = text.lstrip()
    if stripped.startswith("{") or "json" in ct:
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return None
        if not isinstance(data, dict):
            return None
        if isinstance(data.get("openapi"), str):
            return "openapi-3", data
        if isinstance(data.get("swagger"), str):
            return "swagger-2", data
        if "info" in data and "item" in data and isinstance(data.get("item"), list):
            return "postman", data
        if "paths" in data or "definitions" in data or "components" in data:
            return "openapi-3", data
        return None
    # YAML detection — we don't want a PyYAML dependency, so we only
    # return a minimal ``info`` + ``paths`` excerpt by simple regex.
    if "openapi:" in stripped or "swagger:" in stripped:
        return "openapi-3-yaml", stripped
    return None


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
        resp = requests.get(
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
    parsed = _parse_spec_body(body, content_type)
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
) -> list[SpecEndpoint]:
    """Discover API spec endpoints across a set of hosts.

    Args:
        hosts: Hostnames or base URLs to probe.
        extra_paths: Additional relative paths to test.
        max_workers: Max concurrent probes.
        timeout_seconds: Per-probe timeout.

    Returns:
        List of :class:`SpecEndpoint` for every URL that returned a
        recognisable API spec. Endpoints that returned 200 with a
        non-spec body are silently dropped.
    """
    candidate_urls: list[str] = []
    for host in hosts:
        candidate_urls.extend(_candidate_spec_urls(host, extra_paths))
    if not candidate_urls:
        return []

    workers = max(1, min(max_workers, len(candidate_urls)))
    results: list[SpecEndpoint] = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = [
            ex.submit(_probe_spec_url, url, timeout_seconds=timeout_seconds)
            for url in candidate_urls
        ]
        for fut in futures:
            try:
                endpoint = fut.result()
            except Exception as exc:  # noqa: BLE001
                logger.debug("Spec probe future failed: %s", exc)
                continue
            if endpoint is not None:
                results.append(endpoint)
    return results


# ---------------------------------------------------------------------------
# Spec merging
# ---------------------------------------------------------------------------


def merge_openapi_specs(endpoints: Iterable[SpecEndpoint]) -> dict[str, Any]:
    """Merge multiple OpenAPI 3 / Swagger 2 specs into a single OpenAPI 3 doc.

    The output is a *minimal* OpenAPI 3.0.0 document. Each source
    spec contributes its ``paths`` block; identical paths are merged
    with their methods combined. We do NOT attempt full spec
    translation (e.g. ``definitions`` → ``components/schemas``); for
    that operators should use ``openapi-merge`` or
    ``swagger-merger`` externally.
    """
    merged: dict[str, Any] = {
        "openapi": "3.0.0",
        "info": {
            "title": "Reconstructed API surface (cyber-pipeline)",
            "version": "0.0.0",
            "description": (
                "Merged from multiple OpenAPI / Swagger specs discovered during recon."
            ),
        },
        "paths": {},
    }
    seen_paths: set[str] = set()
    for ep in endpoints:
        if not isinstance(ep.spec, dict):
            continue
        paths = ep.spec.get("paths")
        if not isinstance(paths, dict):
            continue
        for path, item in paths.items():
            if not isinstance(item, dict):
                continue
            if path in seen_paths:
                # Merge methods when both specs cover the same path
                for method, op in item.items():
                    if method.lower() in {
                        "get",
                        "post",
                        "put",
                        "patch",
                        "delete",
                        "head",
                        "options",
                        "trace",
                    }:
                        merged["paths"].setdefault(path, {}).setdefault(method, op)
            else:
                seen_paths.add(path)
                merged["paths"][path] = item
    return merged


# ---------------------------------------------------------------------------
# Convenience helpers
# ---------------------------------------------------------------------------


def extract_operation_summaries(spec: dict[str, Any]) -> list[dict[str, Any]]:
    """Pull a flat list of (method, path, summary) tuples from a spec.

    Useful for downstream categorisation in the Nuclei plan builder.
    """
    if not isinstance(spec, dict):
        return []
    paths = spec.get("paths")
    if not isinstance(paths, dict):
        return []
    out: list[dict[str, Any]] = []
    for path, item in paths.items():
        if not isinstance(item, dict):
            continue
        for method, op in item.items():
            if method.lower() not in {
                "get",
                "post",
                "put",
                "patch",
                "delete",
                "head",
                "options",
                "trace",
            }:
                continue
            if not isinstance(op, dict):
                continue
            out.append(
                {
                    "method": method.lower(),
                    "path": path,
                    "operationId": op.get("operationId"),
                    "summary": op.get("summary"),
                    "tags": list(op.get("tags") or []),
                }
            )
    return out


__all__ = [
    "DEFAULT_GRPC_PATHS",
    "DEFAULT_SPEC_PATHS",
    "SpecEndpoint",
    "discover_api_specs",
    "extract_operation_summaries",
    "merge_openapi_specs",
]
