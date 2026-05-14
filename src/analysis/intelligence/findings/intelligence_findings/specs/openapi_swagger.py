"""OpenAPI or Swagger exposure spec."""

from typing import Any

from . import register_spec


def _severity(item: dict[str, Any]) -> str:
    return "medium"


def _description(item: dict[str, Any]) -> str:
    return "Fetch the exposed API spec and map sensitive paths, auth requirements, and forgotten versions."


register_spec(
    (
        "openapi_swagger_spec_checker",
        "exposure",
        _severity,
        "OpenAPI or Swagger exposure",
        _description,
    )
)
