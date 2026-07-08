"""Spec body parsing and content-type detection helpers."""

from __future__ import annotations

import json
import logging
import re
from typing import Any

logger = logging.getLogger(__name__)


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
