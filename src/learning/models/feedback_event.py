"""Feedback event model for the closed-loop learning system.

Represents a single feedback signal from a scan finding that will be used
to influence subsequent scan configurations and detection thresholds.
"""

from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any


@dataclass(frozen=True)
class FeedbackEvent:
    """Represents a single feedback signal from a scan finding.

    Each event captures the outcome of a finding so that future scans
    can be adapted based on what was learned.
    """

    event_id: str
    run_id: str
    timestamp: datetime
    target_host: str
    target_endpoint: str
    finding_category: str
    finding_severity: str
    finding_confidence: float
    finding_decision: str
    plugin_name: str
    parameter_name: str | None = None
    parameter_type: str | None = None
    was_validated: bool = False
    was_false_positive: bool = False
    validation_method: str | None = None
    response_delta_score: int = 0
    endpoint_type: str | None = None
    tech_stack: list[str] = field(default_factory=list)
    scan_mode: str = "deep"
    feedback_weight: float = 1.0

    @classmethod
    def from_finding(
        cls,
        finding: dict[str, Any],
        run_id: str,
        ctx: dict[str, Any] | None = None,
    ) -> FeedbackEvent:
        """Create a FeedbackEvent from a pipeline finding dict.

        Args:
            finding: A merged/classified finding dict from the pipeline.
            run_id: The scan run ID this finding belongs to.
            ctx: Optional pipeline context dict for additional metadata.
        """
        from urllib.parse import urlparse

        url = finding.get("url", "")
        parsed = urlparse(url)
        host = parsed.netloc

        endpoint = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        lifecycle = finding.get("lifecycle_state", "")
        decision = finding.get("decision", "MEDIUM")

        was_validated = lifecycle in ("VALIDATED", "EXPLOITABLE", "REPORTABLE")
        was_fp = decision == "DROP"

        ctx = ctx or {}
        tech_stack = ctx.get("tech_stack", [])
        if not tech_stack:
            tech_stack = finding.get("tech_stack", [])

        event = cls(
            event_id=cls._generate_id(finding, run_id),
            run_id=run_id,
            timestamp=datetime.now(UTC),
            target_host=host,
            target_endpoint=endpoint,
            finding_category=finding.get("category", "unknown"),
            finding_severity=finding.get("severity", "low"),
            finding_confidence=float(finding.get("confidence", 0.0)),
            finding_decision=decision,
            plugin_name=finding.get("module", "unknown"),
            parameter_name=cls._extract_param_from_url(url),
            parameter_type=finding.get("parameter_type"),
            was_validated=was_validated,
            was_false_positive=was_fp,
            validation_method=finding.get("validation_method"),
            response_delta_score=int(finding.get("diff_score", 0)),
            endpoint_type=finding.get("endpoint_type"),
            tech_stack=tech_stack if isinstance(tech_stack, list) else [],
            scan_mode=ctx.get("mode", "deep"),
            feedback_weight=1.0,
        )
        return event

    @staticmethod
    def _generate_id(finding: dict, run_id: str) -> str:
        """Generate a deterministic event ID from finding data."""
        raw = f"{run_id}:{finding.get('id', '')}:{finding.get('url', '')}:{finding.get('category', '')}"
        return f"fb-{hashlib.sha256(raw.encode()).hexdigest()[:16]}"

    @staticmethod
    def _extract_param_from_url(url: str) -> str | None:
        """Extract the first query parameter name from a URL."""
        from urllib.parse import parse_qs, urlparse

        parsed = urlparse(url)
        if parsed.query:
            params = parse_qs(parsed.query)
            if params:
                return next(iter(params.keys()))
        return None

    def compute_weight(
        self,
        decay_rate: float = 0.01,
        reference_time: datetime | None = None,
    ) -> float:
        """Compute the feedback weight for this event.

        weight = base × recency_decay × validation_multiplier × severity_multiplier

        Args:
            decay_rate: Daily decay rate (lambda). Default 0.01.
            reference_time: Time to compute recency against. Defaults to now.
        """
        ref = reference_time or datetime.now(UTC)

        delta_days = max(0, (ref - self.timestamp).total_seconds() / 86400)
        recency_decay = math.exp(-decay_rate * delta_days)

        if self.was_validated and not self.was_false_positive:
            validation_mult = 2.0
        elif self.was_validated and self.was_false_positive:
            validation_mult = 0.3
        elif not self.was_validated and not self.was_false_positive:
            validation_mult = 1.0
        else:
            validation_mult = 0.5

        severity_map = {
            "critical": 2.0,
            "high": 1.5,
            "medium": 1.0,
            "low": 0.5,
            "info": 0.2,
        }
        severity_mult = severity_map.get(self.finding_severity.lower(), 1.0)

        return round(recency_decay * validation_mult * severity_mult, 4)
