"""Recon data models for candidate representation.

Provides the ReconCandidate dataclass used throughout the recon pipeline
to represent discovered subdomains, URLs, and endpoints with scoring metadata.
"""

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class ReconCandidate:
    """Represents a discovered recon target (subdomain, URL, or endpoint).

    Attributes:
        kind: Type of candidate (e.g., 'subdomain', 'url', 'endpoint').
        value: The actual discovered value.
        source: How this candidate was found (e.g., 'crtsh', 'subfinder', 'gau').
        host: Hostname extracted from the value.
        url: Full URL if applicable.
        score: Priority score for ranking.
        metadata: Additional context about this candidate.
    """

    kind: str
    value: str
    source: str
    host: str = ""
    url: str = ""
    score: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)
