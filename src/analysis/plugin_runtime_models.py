"""Data classes for plugin runtime engine.

Extracted from plugin_runtime.py to reduce module size and improve import clarity.
"""

from dataclasses import dataclass
from typing import Any

from src.core.contracts.plugin_types import (
    AnalysisExecutionContext as AnalysisExecutionContext,
)
from src.core.contracts.plugin_types import (
    AnalyzerBinding as AnalyzerBinding,
)

__all__ = [
    "AnalysisExecutionContext",
    "AnalyzerBinding",
    "DetectionGraphContext",
    "EndpointEntity",
    "EvidenceEntity",
    "FlowEdge",
]


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
