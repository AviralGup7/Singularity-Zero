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
* the relevant CWE identifier (when known) and OWASP Top 10 / API
  category, sourced from :data:`CATEGORY_CWE_MAP`
* an optional ``source_location`` (file path + line) when the
  finding's evidence carries it, so engineers know exactly where
  to apply the fix

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


# Category → CWE / OWASP mapping. Used to enrich the remediation
# candidate with a precise identifier the engineering team can look
# up in their secure-coding reference. The keys are matched
# case-insensitively against the finding's ``category`` field.
#
# Sources:
#   - MITRE CWE catalog (https://cwe.mitre.org)
#   - OWASP Top 10 2021 / API Security Top 10 2023
CATEGORY_CWE_MAP: dict[str, dict[str, str]] = {
    "idor": {"cwe": "CWE-639", "owasp": "API1:2023", "owasp_top10": "A01:2021"},
    "bola": {"cwe": "CWE-639", "owasp": "API1:2023", "owasp_top10": "A01:2021"},
    "broken_object_level_authorization": {
        "cwe": "CWE-639",
        "owasp": "API1:2023",
        "owasp_top10": "A01:2021",
    },
    "access_control": {"cwe": "CWE-284", "owasp": "API5:2023", "owasp_top10": "A01:2021"},
    "auth_bypass": {"cwe": "CWE-287", "owasp": "API2:2023", "owasp_top10": "A07:2021"},
    "auth_bypass_no_auth": {"cwe": "CWE-306", "owasp": "API2:2023", "owasp_top10": "A07:2021"},
    "auth_bypass_invalid_token": {
        "cwe": "CWE-345",
        "owasp": "API2:2023",
        "owasp_top10": "A02:2021",
    },
    "authentication_bypass": {"cwe": "CWE-287", "owasp": "API2:2023", "owasp_top10": "A07:2021"},
    "broken_authentication": {"cwe": "CWE-287", "owasp": "API2:2023", "owasp_top10": "A07:2021"},
    "ssrf": {"cwe": "CWE-918", "owasp": "API7:2023", "owasp_top10": "A10:2021"},
    "xss": {"cwe": "CWE-79", "owasp": "API8:2023", "owasp_top10": "A03:2021"},
    "reflected_xss": {"cwe": "CWE-79", "owasp": "API8:2023", "owasp_top10": "A03:2021"},
    "stored_xss": {"cwe": "CWE-79", "owasp": "API8:2023", "owasp_top10": "A03:2021"},
    "sql_injection": {"cwe": "CWE-89", "owasp": "API8:2023", "owasp_top10": "A03:2021"},
    "command_injection": {"cwe": "CWE-78", "owasp": "API8:2023", "owasp_top10": "A03:2021"},
    "ssti": {"cwe": "CWE-1336", "owasp": "API8:2023", "owasp_top10": "A03:2021"},
    "open_redirect": {"cwe": "CWE-601", "owasp": "API1:2023", "owasp_top10": "A01:2021"},
    "unvalidated_redirect": {"cwe": "CWE-601", "owasp": "API1:2023", "owasp_top10": "A01:2021"},
    "csrf": {"cwe": "CWE-352", "owasp": "API2:2023", "owasp_top10": "A01:2021"},
    "race_condition": {"cwe": "CWE-362", "owasp": "API4:2023", "owasp_top10": "A04:2021"},
    "file_upload": {"cwe": "CWE-434", "owasp": "API4:2023", "owasp_top10": "A04:2021"},
    "path_traversal": {"cwe": "CWE-22", "owasp": "API1:2023", "owasp_top10": "A01:2021"},
    "directory_listing": {"cwe": "CWE-548", "owasp": "API3:2023", "owasp_top10": "A05:2021"},
    "information_disclosure": {"cwe": "CWE-200", "owasp": "API3:2023", "owasp_top10": "A04:2021"},
    "info_disclosure": {"cwe": "CWE-200", "owasp": "API3:2023", "owasp_top10": "A04:2021"},
    "token_leak": {"cwe": "CWE-798", "owasp": "API2:2023", "owasp_top10": "A07:2021"},
    "hardcoded_credentials": {"cwe": "CWE-798", "owasp": "API2:2023", "owasp_top10": "A07:2021"},
    "weak_credentials": {"cwe": "CWE-521", "owasp": "API2:2023", "owasp_top10": "A07:2021"},
    "business_logic": {"cwe": "CWE-840", "owasp": "API6:2023", "owasp_top10": "A04:2021"},
    "insecure_deserialization": {"cwe": "CWE-502", "owasp": "API8:2023", "owasp_top10": "A08:2021"},
    "mass_assignment": {"cwe": "CWE-915", "owasp": "API6:2023", "owasp_top10": "A08:2021"},
    "excessive_data_exposure": {"cwe": "CWE-213", "owasp": "API3:2023", "owasp_top10": "A04:2021"},
    "graphql_introspection": {"cwe": "CWE-200", "owasp": "API3:2023", "owasp_top10": "A05:2021"},
    "websocket": {"cwe": "CWE-1385", "owasp": "API2:2023", "owasp_top10": "A07:2021"},
    "jwt": {"cwe": "CWE-347", "owasp": "API2:2023", "owasp_top10": "A02:2021"},
    "smuggling": {"cwe": "CWE-444", "owasp": "API8:2023", "owasp_top10": "A05:2021"},
}


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
    # CWE / OWASP identifiers resolved from CATEGORY_CWE_MAP. Empty
    # when the category is not in the map.
    cwe_id: str = ""
    owasp_api: str = ""
    owasp_top10: str = ""
    # Optional source-location pointers so engineers know where to
    # apply the fix. ``source_file`` is a relative or absolute path;
    # ``source_line`` is a 1-indexed line number; ``source_function``
    # is the function/method name (if known).
    source_file: str = ""
    source_line: int = 0
    source_function: str = ""

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
            "cwe_id": self.cwe_id,
            "owasp_api": self.owasp_api,
            "owasp_top10": self.owasp_top10,
            "source_file": self.source_file,
            "source_line": self.source_line,
            "source_function": self.source_function,
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
    finding_key = str(finding.get("endpoint_key") or evidence.get("endpoint_key") or endpoint)
    fingerprint = _fingerprint(category, endpoint, method, severity)

    # CWE / OWASP resolution. The map key is matched case-insensitively
    # against the finding's category, then we attach the CWE to the
    # candidate. When the finding itself already carries a CWE (e.g. a
    # static-analysis result with ``cwe`` set), we prefer that value.
    cwe_info = CATEGORY_CWE_MAP.get(category, {})
    cwe_id = str(finding.get("cwe") or finding.get("cwe_id") or cwe_info.get("cwe", ""))
    owasp_api = str(finding.get("owasp_api") or cwe_info.get("owasp", ""))
    owasp_top10 = str(finding.get("owasp_top10") or cwe_info.get("owasp_top10", ""))

    # Source-location context. The pipeline's source-fingerprinter
    # (when run) attaches ``source_file`` / ``source_line`` /
    # ``source_function`` to the finding's evidence. We pass them
    # through so engineers can jump straight to the affected code.
    source_file = str(
        evidence.get("source_file") or evidence.get("file") or finding.get("source_file", "")
    )
    try:
        source_line = int(evidence.get("source_line") or evidence.get("line") or 0)
    except (TypeError, ValueError):
        source_line = 0
    source_function = str(
        evidence.get("source_function")
        or evidence.get("function")
        or finding.get("source_function", "")
    )

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
        cwe_id=cwe_id,
        owasp_api=owasp_api,
        owasp_top10=owasp_top10,
        source_file=source_file,
        source_line=source_line,
        source_function=source_function,
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
        candidate = build_remediation_candidate(finding, confidence_threshold=confidence_threshold)
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
    candidates = build_remediation_candidates(findings, confidence_threshold=confidence_threshold)
    state_delta["remediation_candidates"] = [c.to_dict() for c in candidates]
    return candidates


__all__ = [
    "CATEGORY_CWE_MAP",
    "DEFAULT_CONFIDENCE_THRESHOLD",
    "RemediationCandidate",
    "attach_remediation_candidates_to_delta",
    "build_remediation_candidate",
    "build_remediation_candidates",
]
