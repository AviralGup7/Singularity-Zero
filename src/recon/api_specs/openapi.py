"""OpenAPI / Swagger spec parsing, server variable expansion, and merging."""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any

# Default OpenAPI / Swagger discovery paths, in priority order.
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

# AsyncAPI discovery paths
DEFAULT_ASYNCAPI_PATHS: tuple[str, ...] = (
    "/asyncapi.json",
    "/asyncapi.yaml",
    "/asyncapi.yml",
    ".well-known/asyncapi.json",
    ".well-known/asyncapi.yaml",
)

# GraphQL SDL / schema endpoint discovery paths
DEFAULT_GRAPHQL_SDL_PATHS: tuple[str, ...] = (
    "/graphql/schema",
    "/graphql/sdl.json",
    "/graphql/sdl",
    "/graphql/graphql.schema.json",
    "/graphql/swagger.json",
)

# Thrift IDL discovery paths
DEFAULT_THRIFT_PATHS: tuple[str, ...] = (
    "/thrift/api.thrift",
    "/api.thrift",
)

# Avro schema discovery paths
DEFAULT_AVRO_PATHS: tuple[str, ...] = ("/avro/schema.avsc",)

# OpenAPI server variables to substitute when {var} placeholders are found
DEFAULT_SERVER_VARIABLES: dict[str, list[str]] = {
    "env": ["prod", "staging", "dev", "qa", "uat", "test", "local"],
    "region": [
        "us",
        "eu",
        "ap",
        "sa",
        "au",
        "ca",
        "us-east-1",
        "us-west-2",
        "eu-west-1",
        "ap-southeast-1",
    ],
    "version": ["v1", "v2", "v3"],
    "stage": ["prod", "staging", "dev"],
}

_OPENAPI_SERVER_VAR_RE = re.compile(r"\{[^}]+\}")


def _expand_server_variables(url: str, variables: dict[str, list[str]] | None = None) -> list[str]:
    vars_map = variables if variables is not None else DEFAULT_SERVER_VARIABLES
    if not _OPENAPI_SERVER_VAR_RE.search(url):
        return [url]
    expanded: list[str] = [url]
    for var_name, values in vars_map.items():
        placeholder = "{" + var_name + "}"
        if placeholder in url:
            new_urls: list[str] = []
            for existing in expanded:
                for val in values:
                    new_urls.append(existing.replace(placeholder, val))
            expanded = new_urls
    return expanded


def _extract_base_urls_from_spec(spec: Any) -> list[str]:
    urls: list[str] = []
    if not isinstance(spec, dict):
        return urls
    servers = spec.get("servers")
    if isinstance(servers, list):
        for srv in servers:
            if isinstance(srv, dict) and isinstance(srv.get("url"), str):
                url = srv["url"].strip()
                for expanded in _expand_server_variables(url):
                    if expanded not in urls:
                        urls.append(expanded)
    if not urls and isinstance(spec.get("host"), str):
        urls.append(spec["host"])
    if not urls and isinstance(spec.get("basePath"), str):
        urls.append(spec["basePath"])
    if not urls and isinstance(spec.get("servers"), dict):
        url = spec["servers"].get("url")
        if isinstance(url, str):
            urls.extend(_expand_server_variables(url))
    return urls


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
                    1
                    for k in path_item
                    if k.lower()
                    in {"get", "post", "put", "patch", "delete", "head", "options", "trace"}
                )
        return total
