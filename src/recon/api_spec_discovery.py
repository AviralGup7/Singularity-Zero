"""OpenAPI / Swagger / GraphQL introspection / AsyncAPI / gRPC / Thrift / Avro discovery.

Modern APIs almost always publish a machine-readable schema:

* REST APIs: ``/openapi.json``, ``/openapi.yaml``, ``/swagger.json``,
  ``/v1/api-docs``, ``/v2/api-docs``, ``/v3/api-docs``,
  ``/swagger-resources``, ``/api/swagger``, ``/api/openapi``, etc.
* AsyncAPI: ``/asyncapi.json``, ``/asyncapi.yaml``, ``/.well-known/asyncapi.json``
* GraphQL SDL: ``/graphql/schema``, ``/graphql/sdl.json``, ``/graphql/sdl``
* gRPC: reflection endpoint, ``/.well-known/proto.txt``, ``/protos.desc``,
  ``/api/proto``, ``/api/v1/proto``, ``/proto``, ``/protos``
* Protobuf descriptors: ``/protos.desc``
* Thrift IDL: ``/thrift/api.thrift``, ``/api.thrift``
* Avro schema: ``/avro/schema.avsc``
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
import re
import subprocess
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor
from typing import Any
from urllib.parse import urljoin, urlparse

import requests

from src.recon.url_validation import is_safe_url

logger = logging.getLogger(__name__)

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

# Protobuf / .proto discovery paths
DEFAULT_PROTO_PATHS: tuple[str, ...] = (
    ".well-known/proto.txt",
    "/protos.desc",
    "/api/proto",
    "/api/v1/proto",
    "/proto",
    "/protos",
    "/api/protos",
)

# gRPC-Web endpoint detection patterns
DEFAULT_GRPC_WEB_PATHS: tuple[str, ...] = (
    "/grpcweb",
    "/grpcweb.JS",
    "/_grpcgateway",
    "/api.grpc",
    "/swagger.json",
)

# Thrift IDL discovery paths
DEFAULT_THRIFT_PATHS: tuple[str, ...] = (
    "/thrift/api.thrift",
    "/api.thrift",
)

# Avro schema discovery paths
DEFAULT_AVRO_PATHS: tuple[str, ...] = ("/avro/schema.avsc",)

# gRPC reflection hints
DEFAULT_GRPC_PATHS: tuple[str, ...] = (
    "/grpc.reflection.v1.ServerReflection",
    "/grpc.reflection.v1alpha.ServerReflection",
    "/grpc.health.v1.Health",
)

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
                    1
                    for k in path_item
                    if k.lower()
                    in {"get", "post", "put", "patch", "delete", "head", "options", "trace"}
                )
        return total


# ---------------------------------------------------------------------------
# Spec parsing
# ---------------------------------------------------------------------------


def _yaml_parse_available() -> bool:
    try:
        import yaml  # noqa: F401

        return True
    except ImportError:
        return False


def _try_parse_yaml(text: str) -> Any | None:
    if not text:
        return None
    if _yaml_parse_available():
        try:
            import yaml

            return yaml.safe_load(text)
        except Exception:
            return None
    stripped = text.lstrip()
    if (
        "openapi:" in stripped[:512]
        or "asyncapi:" in stripped[:512]
        or "swagger:" in stripped[:512]
    ):
        return {"__yaml_raw__": stripped[:4096]}
    return None


def _looks_like_asyncapi(text: str) -> bool:
    if not text:
        return False
    stripped = text.lstrip()
    if stripped.startswith("{"):
        return "asyncapi" in stripped[:1024]
    if stripped.startswith("---") or stripped.startswith("asyncapi:"):
        return True
    return False


def _looks_like_graphql_sdl(text: str) -> bool:
    if not text:
        return False
    stripped = text.lstrip().lower()
    if stripped.startswith("{"):
        try:
            data = json.loads(text)
            if isinstance(data, dict) and ("data" in data or "__schema" in data):
                return True
        except Exception as exc:
            logger.warning("Operation failed in api_spec_discovery.py: %s", exc, exc_info=True)  # noqa: BLE001
        return False
    if any(
        kw in stripped[:1024]
        for kw in ["type query", "type mutation", "enum ", "input ", "scalar "]
    ):
        return True
    return False


def _looks_like_proto(text: str) -> bool:
    if not text:
        return False
    stripped = text.lstrip().lower()
    return (
        stripped.startswith("syntax")
        or "message " in stripped[:2048]
        or "service " in stripped[:2048]
        or "package " in stripped[:2048]
        or "option " in stripped[:2048]
    )


def _looks_like_thrift(text: str) -> bool:
    if not text:
        return False
    stripped = text.lstrip().lower()
    return (
        stripped.startswith("namespace")
        or "struct " in stripped[:2048]
        or "service " in stripped[:2048]
        or "typedef " in stripped[:2048]
    )


def _looks_like_avro(text: str) -> bool:
    if not text:
        return False
    try:
        data = json.loads(text)
        if isinstance(data, dict) and data.get("type") == "record" and "name" in data:
            return True
        if isinstance(data, dict) and "fields" in data:
            return True
    except Exception as exc:
        logger.warning("Operation failed in api_spec_discovery.py: %s", exc, exc_info=True)  # noqa: BLE001
    return False


_GRPCWEB_CT_RE = re.compile(r"application/grpc-web", re.IGNORECASE)
_GRPC_GATEWAY_CT_RE = re.compile(r"application/grpc-gateway", re.IGNORECASE)


def _looks_like_grpc_web(content_type: str, body: str) -> bool:
    ct = (content_type or "").lower()
    if _GRPCWEB_CT_RE.search(ct) or _GRPC_GATEWAY_CT_RE.search(ct):
        return True
    if "grpc-web" in body.lower()[:2048] or "x-grpc-web" in body.lower()[:2048]:
        return True
    return False


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
# gRPC reflection via grpcurl
# ---------------------------------------------------------------------------


def _grpcurl_reflection_available() -> bool:
    try:
        subprocess.run(["grpcurl", "--version"], capture_output=True, check=True, timeout=5)
        return True
    except (FileNotFoundError, subprocess.SubprocessError, OSError, ValueError):
        return False


_GRPCURL_REFLECTION_DESCRIPTORS: str = "descriptors"


def grpcurl_list_services(host: str, *, timeout_seconds: int = 10) -> list[str]:
    if not _grpcurl_reflection_available():
        logger.debug("grpcurl not available on PATH, skipping gRPC reflection")
        return []
    host = (host or "").strip()
    if not host:
        return []
    target = host if "://" in host else f"{host}:443"
    try:
        result = subprocess.run(
            ["grpcurl", "-plaintext" if target.startswith("localhost") else "", target, "list"],
            capture_output=True,
            text=True,
            timeout=max(5, timeout_seconds),
        )
    except subprocess.SubprocessError as exc:
        logger.debug("grpcurl list failed for %s: %s", target, exc)
        return []
    if result.returncode != 0:
        return []
    services: list[str] = []
    for line in (result.stdout or "").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            services.append(line)
    return services


def grpcurl_describe_service(
    host: str, service: str, *, timeout_seconds: int = 10
) -> dict[str, Any] | None:
    if not _grpcurl_reflection_available():
        return None
    host = (host or "").strip()
    if not host:
        return None
    target = host if "://" in host else f"{host}:443"
    try:
        result = subprocess.run(
            [
                "grpcurl",
                "-plaintext" if target.startswith("localhost") else "",
                target,
                "describe",
                service,
            ],
            capture_output=True,
            text=True,
            timeout=max(5, timeout_seconds),
        )
    except subprocess.SubprocessError as exc:
        logger.debug("grpcurl describe failed for %s/%s: %s", target, service, exc)
        return None
    if result.returncode != 0:
        return None
    return {
        "host": host,
        "service": service,
        "describe_output": result.stdout.strip(),
        "stderr": result.stderr.strip(),
    }


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
        resp = requests.get(
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


def _parse_spec_body_enhanced(text: str, content_type: str) -> tuple[str, Any] | None:
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
        if isinstance(data.get("asyncapi"), str):
            return "asyncapi", data
        if isinstance(data.get("openapi"), str):
            return "openapi-3", data
        if isinstance(data.get("swagger"), str):
            return "swagger-2", data
        if "info" in data and "item" in data and isinstance(data.get("item"), list):
            return "postman", data
        if "__schema" in data or "data" in data and isinstance(data.get("data"), dict):
            try:
                inner = data.get("data", {})
                if isinstance(inner, dict) and inner.get("__schema"):
                    return "graphql-sdl-json", data
            except Exception as exc:
                logger.warning("Operation failed in api_spec_discovery.py: %s", exc, exc_info=True)  # noqa: BLE001
        return None
    parsed_yaml = _try_parse_yaml(text)
    if parsed_yaml is not None:
        if isinstance(parsed_yaml, dict):
            if "asyncapi" in parsed_yaml:
                return "asyncapi", parsed_yaml
            if "openapi" in parsed_yaml:
                return "openapi-3", parsed_yaml
            if "swagger" in parsed_yaml:
                return "swagger-2", parsed_yaml
        if _looks_like_asyncapi(text):
            return "asyncapi-yaml", parsed_yaml
        if "openapi:" in stripped or "swagger:" in stripped:
            return "openapi-3-yaml", parsed_yaml
        return None
    if _looks_like_graphql_sdl(text):
        return "graphql-sdl", text.strip()
    if _looks_like_proto(text):
        return "proto", text.strip()
    if _looks_like_thrift(text):
        return "thrift", text.strip()
    if _looks_like_avro(text):
        return "avro", text.strip() if stripped.startswith("{") else json.loads(text)
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

    workers = max(1, min(max_workers, len(candidate_urls)))
    results: list[SpecEndpoint] = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = [
            ex.submit(
                _probe,
                url,
                timeout_seconds=timeout_seconds,
                auth_headers=merged_auth if _probe is _probe_spec_url_with_auth else None,
            )
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
    "DEFAULT_ASYNCAPI_PATHS",
    "DEFAULT_AVRO_PATHS",
    "DEFAULT_GRAPHQL_SDL_PATHS",
    "DEFAULT_GRPC_PATHS",
    "DEFAULT_GRPC_WEB_PATHS",
    "DEFAULT_PROTO_PATHS",
    "DEFAULT_SPEC_PATHS",
    "DEFAULT_SERVER_VARIABLES",
    "DEFAULT_THRIFT_PATHS",
    "SpecEndpoint",
    "discover_api_specs",
    "extract_auth_headers_from_js_parsers",
    "extract_operation_summaries",
    "grpcurl_describe_service",
    "grpcurl_list_services",
    "merge_openapi_specs",
]
