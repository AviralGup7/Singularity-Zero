"""Data classes for plugin runtime engine.

Extracted from plugin_runtime.py to reduce module size and improve import clarity.
"""

from dataclasses import dataclass
from typing import Any

__all__ = [
    "AnalysisExecutionContext",
    "AnalyzerBinding",
    "DetectionGraphContext",
    "EndpointEntity",
    "EvidenceEntity",
    "FlowEdge",
]


@dataclass
class AnalysisExecutionContext:
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


@dataclass
class AnalyzerBinding:
    input_kind: str
    runner: object | None = None
    context_attr: str | None = None
    limit_key: str | None = None
    default_limit: int | None = None
    phase: str = "discover"
    consumes: tuple[str, ...] = ()
    produces: tuple[str, ...] = ()
    extra_kwargs: dict[str, object] | None = None


@dataclass(frozen=True)
class EndpointEntity:
    endpoint_key: str
    url: str
    host: str
    query_parameters: tuple[str, ...] = ()


@dataclass(frozen=True)
class IdentityEntity:
    identity_key: str
    role: str = "unknown"
    token: str = ""


@dataclass(frozen=True)
class FlowEdge:
    source_key: str
    target_key: str
    edge_type: str
    confidence: float = 0.5


@dataclass
class MutationResult:
    url: str
    mutation_type: str
    status_code: int | None = None
    body_similarity: float = 1.0
    changed: bool = False


@dataclass(frozen=True)
class EvidenceEntity:
    analyzer_key: str
    phase: str
    url: str
    summary: str
    severity: str = "info"
    metadata: dict[str, object] | None = None


@dataclass
class DetectionGraphContext:
    execution: AnalysisExecutionContext
    endpoints: dict[str, EndpointEntity]
    identities: dict[str, IdentityEntity]
    flow_edges: list[FlowEdge]
    mutation_results: list[MutationResult]
    evidence: list[EvidenceEntity]
    artifacts: dict[str, object]
    results: dict[str, list[dict[str, Any]]]

    def has_artifacts(self, names: tuple[str, ...]) -> bool:
        return all(name in self.artifacts for name in names)

    def put_artifact(self, name: str, value: object) -> None:
        self.artifacts[name] = value
