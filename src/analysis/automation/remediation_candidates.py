"""Remediation candidate emission for high-confidence access-control findings.

A :class:`RemediationCandidate` is a structured, machine-readable
description of a fix that *could* be applied to a finding.  These
candidates are emitted into the pipeline ``state_delta`` so that
downstream consumers (a WAF virtual-patch enforcer, an IAM policy
updater, a ticket creator) can pick them up without needing to
re-parse the original finding.

For :class:`AccessControlAnalyzer` results that meet the
``confidence_threshold`` (default ``0.85``), the builder attaches:

* the original endpoint, method, and tested auth context
* the categories of test that fired (``no_auth``, ``invalid_token``)
* a suggested fix string (human-readable)
* a SHA-1 fingerprint so consumers can dedup
* a list of ``evidence_keys`` for traceability

The candidate does **not** carry an executable payload — the goal is
to bridge analysis and remediation, not to *be* the remediation.
"""

from __future__ import annotations

import hashlib
import logging
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


DEFAULT_CONFIDENCE_THRESHOLD: float = 0.85


_SEVERITY_TO_REMEDIATION_PROMPT: dict[str, str] = {
    "no_auth": (
        "Enforce endpoint-level authentication on the protected resource; "
        "tested with no_auth context — resource was accessible without "
        "credentials."
    ),
    "invalid_token": (
        "Validate the JWT/Authorization header on the protected resource; "
        "tested with invalid_token context — the resource accepted a "
        "Bearer token that is known to be invalid."
    ),
}


@dataclass(frozen=True, slots=True)
class RemediationCandidate:
    """Structured remediation suggestion emitted into ``state_delta``."""

    finding_key: str
    endpoint: str
    method: str
    category: str
    severity: str
    confidence: float
    test_contexts: tuple[str, ...]
    suggested_fix: str
    fingerprint: str
    evidence_keys: tuple[str, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_key": self.finding_key,
            "endpoint": self.endpoint,
            "method": self.method,
            "category": self.category,
            "severity": self.severity,
            "confidence": round(self.confidence, 3),
            "test_contexts": list(self.test_contexts),
            "suggested_fix": self.suggested_fix,
            "fingerprint": self.fingerprint,
            "evidence_keys": list(self.evidence_keys),
            "metadata": dict(self.metadata),
        }


def _fingerprint(*parts: str) -> str:
    payload = "|".join(parts).encode("utf-8")
    return hashlib.sha1(payload).hexdigest()


def _coerce_confidence(value: Any, *, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def build_remediation_candidate(
    finding: Mapping[str, Any],
    *,
    confidence_threshold: float = DEFAULT_CONFIDENCE_THRESHOLD,
) -> RemediationCandidate | None:
    """Build a :class:`RemediationCandidate` from a finding dict.

    Returns ``None`` when the finding's category is not
    ``access_control*`` or its confidence is below the threshold.
    """
    if not isinstance(finding, Mapping):
        return None

    category = str(finding.get("category", "")).lower()
    if not category.startswith("access_control") and category not in {
        "auth_bypass_no_auth",
        "auth_bypass_invalid_token",
    }:
        return None

    confidence = _coerce_confidence(finding.get("confidence", 0))
    if confidence < confidence_threshold:
        return None

    endpoint = str(finding.get("url", "")).strip()
    method = str(finding.get("method", "GET")).strip().upper() or "GET"
    severity = str(finding.get("severity", "high")).strip().lower() or "high"
    evidence = finding.get("evidence", {}) or {}
    if not isinstance(evidence, Mapping):
        evidence = {}

    test_context = str(evidence.get("test_context", "no_auth"))
    test_contexts: tuple[str, ...]
    if test_context:
        test_contexts = (test_context,)
    else:
        test_contexts = ("no_auth",)

    suggested_fix = _SEVERITY_TO_REMEDIATION_PROMPT.get(
        test_context,
        "Audit the endpoint's authorization check; tested with the contexts "
        f"{', '.join(test_contexts)}.",
    )

    evidence_keys = tuple(sorted(str(k) for k in evidence.keys()))
    finding_key = str(
        finding.get("endpoint_key")
        or evidence.get("endpoint_key")
        or endpoint
    )
    fingerprint = _fingerprint(category, endpoint, method, severity)

    return RemediationCandidate(
        finding_key=finding_key,
        endpoint=endpoint,
        method=method,
        category=category,
        severity=severity,
        confidence=confidence,
        test_contexts=test_contexts,
        suggested_fix=suggested_fix,
        fingerprint=fingerprint,
        evidence_keys=evidence_keys,
        metadata={
            "details": str(evidence.get("details", "")),
            "original_status": evidence.get("original_status"),
            "test_status": evidence.get("test_status"),
        },
    )


def build_remediation_candidates(
    findings: Iterable[Mapping[str, Any]],
    *,
    confidence_threshold: float = DEFAULT_CONFIDENCE_THRESHOLD,
) -> list[RemediationCandidate]:
    """Project a sequence of findings into :class:`RemediationCandidate` list.

    Drops low-confidence findings and de-duplicates by fingerprint so
    the downstream consumer sees at most one candidate per
    (category, endpoint, method, severity) tuple.
    """
    seen: set[str] = set()
    out: list[RemediationCandidate] = []
    for finding in findings:
        candidate = build_remediation_candidate(
            finding, confidence_threshold=confidence_threshold
        )
        if candidate is None:
            continue
        if candidate.fingerprint in seen:
            continue
        seen.add(candidate.fingerprint)
        out.append(candidate)
    return out


def attach_remediation_candidates_to_delta(
    state_delta: dict[str, Any],
    findings: Iterable[Mapping[str, Any]],
    *,
    confidence_threshold: float = DEFAULT_CONFIDENCE_THRESHOLD,
) -> list[RemediationCandidate]:
    """Mutate ``state_delta`` in place, returning the candidates emitted.

    Idempotent: replaces any previous ``remediation_candidates`` key.
    """
    candidates = build_remediation_candidates(
        findings, confidence_threshold=confidence_threshold
    )
    state_delta["remediation_candidates"] = [c.to_dict() for c in candidates]
    return candidates


__all__ = [
    "DEFAULT_CONFIDENCE_THRESHOLD",
    "RemediationCandidate",
    "attach_remediation_candidates_to_delta",
    "build_remediation_candidate",
    "build_remediation_candidates",
]
