"""Shared plugin types for analysis and detection layers.

This module provides shared data classes that are used by both analysis
and detection packages, breaking the circular dependency between them.
"""

from dataclasses import dataclass
from typing import Any


@dataclass
class AnalysisExecutionContext:
    """Context for analysis plugin execution."""

    live_hosts: set[str]
    urls: set[str]
    priority_urls: set[str]
    analysis_config: dict[str, object]
    header_targets: list[str]
    responses: list[dict[str, Any]]
    response_map: dict[str, dict[str, Any]]
    response_cache: object
    ranked_items: list[dict[str, Any]]
    flow_items: list[dict[str, Any]]
    bulk_items: list[dict[str, Any]]
    payload_items: list[dict[str, Any]]
    token_findings: list[dict[str, Any]]
    csrf_findings: list[dict[str, Any]]
    ssti_findings: list[dict[str, Any]]
    upload_findings: list[dict[str, Any]]
    business_logic_findings: list[dict[str, Any]]
    rate_limit_findings: list[dict[str, Any]]
    jwt_findings: list[dict[str, Any]]
    smuggling_findings: list[dict[str, Any]]
    ssrf_findings: list[dict[str, Any]]
    idor_findings: list[dict[str, Any]]


class LazyRunnerDescriptor:
    def __get__(self, instance: Any, owner: Any) -> Any:
        if instance is None:
            return self
        val = instance.__dict__.get("runner")
        if hasattr(val, "__lazy_resolve__"):
            val = val.__lazy_resolve__()
            instance.__dict__["runner"] = val
        return val

    def __set__(self, instance: Any, value: Any) -> None:
        if isinstance(value, LazyRunnerDescriptor):
            value = None
        instance.__dict__["runner"] = value


@dataclass
class AnalyzerBinding:
    """Binding for an analyzer plugin."""

    input_kind: str
    runner: Any | None = None
    context_attr: str | None = None
    limit_key: str | None = None
    default_limit: int | None = None
    phase: str = "discover"
    consumes: tuple[str, ...] = ()
    produces: tuple[str, ...] = ()
    extra_kwargs: dict[str, object] | None = None

    runner = LazyRunnerDescriptor()


@dataclass(frozen=True)
class DetectionGraphContext:
    """Context for detection graph operations."""

    endpoint_entities: tuple[Any, ...] = ()
    flow_edges: tuple[Any, ...] = ()
    evidence_entities: tuple[Any, ...] = ()
