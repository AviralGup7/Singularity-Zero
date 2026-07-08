"""gRPC reflection via grpcurl."""

from __future__ import annotations

import logging
import subprocess
from typing import Any

logger = logging.getLogger(__name__)

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

# gRPC reflection hints
DEFAULT_GRPC_PATHS: tuple[str, ...] = (
    "/grpc.reflection.v1.ServerReflection",
    "/grpc.reflection.v1alpha.ServerReflection",
    "/grpc.health.v1.Health",
)


def _grpcurl_reflection_available() -> bool:
    try:
        subprocess.run(["grpcurl", "--version"], capture_output=True, check=True, timeout=5)  # noqa: S607
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
        result = subprocess.run(  # noqa: S603
            ["grpcurl", "-plaintext" if target.startswith("localhost") else "", target, "list"],  # noqa: S607
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
        result = subprocess.run(  # noqa: S603
            [  # noqa: S607
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
