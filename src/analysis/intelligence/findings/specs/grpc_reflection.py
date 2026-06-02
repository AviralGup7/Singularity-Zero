"""gRPC reflection exposure hint spec."""

from typing import Any

from . import register_spec


def _severity(item: dict[str, Any]) -> str:
    return "medium"


def _description(item: dict[str, Any]) -> str:
    return "Confirm whether server reflection is enabled and enumerate service names safely."


register_spec(
    (
        "grpc_reflection_exposure_checker",
        "exposure",
        _severity,
        "gRPC reflection exposure hint",
        _description,
    )
)
