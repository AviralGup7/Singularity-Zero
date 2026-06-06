"""Structured detection finding model.

Introduces a typed `DetectionFinding` that wraps the historical
``list[dict[str, Any]]`` contract with first-class confidence scoring,
exploitability classification, and explicit engine-referral metadata so the
exploitation layer can consume detection output to drive what to attack next.

The wrapper is intentionally additive — every existing detector keeps
emitting dicts and the runtime converts them into DetectionFinding on
collection. Downstream code can opt into the new fields without breaking the
old ``dict.get('indicator')`` callers.
"""

from __future__ import annotations

import enum
import hashlib
import json
import logging
import math
import time
import uuid
from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


class Exploitability(enum.StrEnum):
    """Confidence that the finding can be turned into a real exploit."""

    UNKNOWN = "unknown"
    THEORETICAL = "theoretical"
    PROBABLE = "probable"
    CONFIRMED = "confirmed"


class Severity(enum.StrEnum):
    """Severity bucket — kept in sync with reporting conventions."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# -- Confidence scoring helpers ------------------------------------------------

_CONFIDENCE_FLOOR = 0.05
_CONFIDENCE_CEIL = 0.99


def clamp_confidence(value: float) -> float:
    """Clamp any float into the legal [0.05, 0.99] confidence range."""

    if math.isnan(value):
        return _CONFIDENCE_FLOOR
    return max(_CONFIDENCE_FLOOR, min(_CONFIDENCE_CEIL, float(value)))


# -- Data classes --------------------------------------------------------------


@dataclass(slots=True)
class Evidence:
    """Single piece of evidence backing a finding."""

    kind: str
    description: str
    payload: str | None = None
    response_status: int | None = None
    response_length: int | None = None
    body_snippet: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class FindingOverrides:
    """Optional override knobs for callers constructing a finding by hand."""

    severity: Severity | None = None
    confidence: float | None = None
    exploitability: Exploitability | None = None
    recommended_engines: tuple[str, ...] = ()
    remediation_hint: str | None = None
    cwe_id: str | None = None
    cve_id: str | None = None
    tags: tuple[str, ...] = ()


@dataclass(slots=True)
class DetectionFinding:
    """Typed detection finding bridging detection and exploitation layers."""

    finding_id: str
    url: str
    indicator: str
    summary: str
    severity: Severity
    confidence: float
    exploitability: Exploitability
    analyzer_key: str
    phase: str
    recommended_engines: tuple[str, ...]
    evidence: tuple[Evidence, ...]
    remediation_hint: str | None = None
    cwe_id: str | None = None
    cve_id: str | None = None
    tags: tuple[str, ...] = ()
    produced_at: float = field(default_factory=lambda: time.time())
    metadata: dict[str, Any] = field(default_factory=dict)
    # Backward-compat hitches — the dict body is exposed in to_dict().
    legacy: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable dict preserving the old shape."""

        body: dict[str, Any] = {
            "url": self.url,
            "indicator": self.indicator,
            "summary": self.summary,
            "severity": self.severity.value,
            "confidence": round(self.confidence, 3),
            "exploitability": self.exploitability.value,
            "analyzer_key": self.analyzer_key,
            "phase": self.phase,
            "recommended_engines": list(self.recommended_engines),
            "remediation_hint": self.remediation_hint,
            "cwe_id": self.cwe_id,
            "cve_id": self.cve_id,
            "tags": list(self.tags),
            "produced_at": self.produced_at,
            "evidence": [
                {
                    "kind": ev.kind,
                    "description": ev.description,
                    "payload": ev.payload,
                    "response_status": ev.response_status,
                    "response_length": ev.response_length,
                    "body_snippet": ev.body_snippet,
                    **({"extra": ev.extra} if ev.extra else {}),
                }
                for ev in self.evidence
            ],
            "finding_id": self.finding_id,
        }
        body.update(self.metadata)
        if self.legacy:
            body["legacy"] = self.legacy
        return body

    # Backward compatibility — many existing callers test "url" in finding.
    def __getitem__(self, key: str) -> Any:
        if key == "url":
            return self.url
        if key == "indicator":
            return self.indicator
        if key == "severity":
            return self.severity.value
        if key == "confidence":
            return self.confidence
        if key == "exploitability":
            return self.exploitability.value
        if key == "analyzer_key":
            return self.analyzer_key
        if key == "phase":
            return self.phase
        if key == "recommended_engines":
            return list(self.recommended_engines)
        if key == "evidence":
            return [asdict(ev) for ev in self.evidence]
        if key == "finding_id":
            return self.finding_id
        if key == "summary":
            return self.summary
        if key in self.metadata:
            return self.metadata[key]
        raise KeyError(key)

    def get(self, key: str, default: Any = None) -> Any:
        try:
            return self[key]
        except KeyError:
            return default

    def __contains__(self, key: str) -> bool:
        try:
            self[key]
            return True
        except KeyError:
            return False


# -- Construction --------------------------------------------------------------


def _stable_id(url: str, indicator: str, signature: str) -> str:
    payload = f"{url.strip()}|{indicator.strip()}|{signature.strip()}"
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]
    return f"F-{digest}"


def make_finding_id() -> str:
    """Return a fresh unique finding ID — preferred for ephemeral findings."""

    return f"F-{uuid.uuid4().hex[:16]}"


def from_dict(
    raw: Mapping[str, Any],
    *,
    analyzer_key: str,
    phase: str,
    url: str | None = None,
) -> DetectionFinding:
    """Wrap an analyzer's raw dict into a typed `DetectionFinding`.

    The conversion is best-effort: missing fields fall back to safe defaults
    and the original dict is preserved in `legacy` for debuggability.
    """

    raw_url = str(url if url is not None else raw.get("url", "")).strip()
    indicator = str(raw.get("indicator", raw.get("category", "unknown"))).strip()
    summary = str(raw.get("summary", raw.get("description", indicator))).strip()
    severity_str = str(raw.get("severity", "info")).lower()
    try:
        severity = Severity(severity_str)
    except ValueError:
        severity = Severity.INFO

    confidence_raw = raw.get("confidence")
    if confidence_raw is None:
        confidence = _infer_confidence(raw)
    else:
        try:
            confidence = clamp_confidence(float(confidence_raw))
        except (TypeError, ValueError):
            confidence = _infer_confidence(raw)

    exploitability = _infer_exploitability(raw, confidence=confidence)
    engines = tuple(raw.get("recommended_engines") or ())
    evidence = _build_evidence_from_dict(raw)
    sig = _signature_from_dict(raw)
    finding_id = str(raw.get("finding_id") or _stable_id(raw_url, indicator, sig))

    return DetectionFinding(
        finding_id=finding_id,
        url=raw_url,
        indicator=indicator,
        summary=summary,
        severity=severity,
        confidence=confidence,
        exploitability=exploitability,
        analyzer_key=analyzer_key,
        phase=phase,
        recommended_engines=engines,
        evidence=evidence,
        remediation_hint=raw.get("remediation_hint"),
        cwe_id=raw.get("cwe_id"),
        cve_id=raw.get("cve_id"),
        tags=tuple(raw.get("tags") or ()),
        metadata=_metadata_from_dict(raw),
        legacy=dict(raw),
    )


# -- Confidence & exploitability inference -------------------------------------


def _signature_from_dict(raw: Mapping[str, Any]) -> str:
    """Build a short signature for de-duplication."""

    candidate_keys = (
        "parameter",
        "param",
        "field",
        "value",
        "payload",
        "mutation",
        "pattern",
        "indicator",
        "category",
        "endpoint",
    )
    parts: list[str] = []
    for key in candidate_keys:
        if key in raw and raw[key] is not None:
            parts.append(f"{key}={raw[key]}")
    if not parts:
        body = raw.get("body_text") or raw.get("body") or ""
        if isinstance(body, str):
            parts.append(f"body={hashlib.sha256(body.encode('utf-8')).hexdigest()[:8]}")
    return "|".join(parts) or json.dumps({k: raw[k] for k in sorted(raw) if k != "url"}, default=str)[:120]


def _build_evidence_from_dict(raw: Mapping[str, Any]) -> tuple[Evidence, ...]:
    if "evidence" in raw and isinstance(raw["evidence"], list):
        out: list[Evidence] = []
        for item in raw["evidence"]:
            if isinstance(item, Mapping):
                out.append(
                    Evidence(
                        kind=str(item.get("kind", "observation")),
                        description=str(item.get("description", item.get("note", ""))),
                        payload=item.get("payload"),
                        response_status=item.get("response_status") or item.get("status_code"),
                        response_length=item.get("response_length") or item.get("body_length"),
                        body_snippet=item.get("body_snippet") or item.get("body_preview"),
                        extra={k: v for k, v in item.items() if k not in {
                            "kind", "description", "payload", "response_status",
                            "status_code", "response_length", "body_length",
                            "body_snippet", "body_preview",
                        }},
                    )
                )
        return tuple(out)
    if raw.get("status_code") is not None or raw.get("body_preview") is not None:
        return (
            Evidence(
                kind="response",
                description="response from initial probe",
                payload=raw.get("payload"),
                response_status=raw.get("status_code"),
                response_length=raw.get("body_length") or raw.get("content_length"),
                body_snippet=raw.get("body_preview") or raw.get("value_preview"),
            ),
        )
    return ()


def _metadata_from_dict(raw: Mapping[str, Any]) -> dict[str, Any]:
    skip = {
        "url", "indicator", "summary", "description", "severity", "confidence",
        "exploitability", "analyzer_key", "phase", "recommended_engines",
        "remediation_hint", "cwe_id", "cve_id", "tags", "evidence",
        "finding_id", "category",
    }
    return {k: v for k, v in raw.items() if k not in skip and not isinstance(v, (list, dict))}


def _infer_confidence(raw: Mapping[str, Any]) -> float:
    """Best-effort confidence inference for raw analyzer findings.

    Heuristics are deliberately conservative — under-claiming is preferable to
    sending low-quality findings to the exploitation layer.
    """

    base = 0.30  # conservative starting point
    indicator = str(raw.get("indicator", "")).lower()

    strong_indicators = {
        "stored_xss_candidate",
        "reflected_input_candidate",
        "dom_xss_candidate",
        "race_condition_candidate",
        "ssrf_candidate_finder",
        "idor_candidate_finder",
        "sql_error_exposure",
        "command_injection",
        "remote_code_execution",
    }
    if indicator in strong_indicators:
        base = 0.55
    medium_indicators = {
        "open_redirect_candidate",
        "csrf_protection_missing",
        "cors_misconfig",
        "cookie_security_issue",
        "header_checker_finding",
        "waf_challenge_page",
    }
    if indicator in medium_indicators:
        base = 0.40

    if raw.get("status_code") in (500, 502, 503):
        base += 0.05
    if raw.get("status_drift"):
        base += 0.05
    if raw.get("diff") and isinstance(raw["diff"], Mapping) and raw["diff"].get("status_changed"):
        base += 0.05
    if raw.get("body_changed"):
        base += 0.05
    if raw.get("xss_signals") or raw.get("signals"):
        base += 0.05
    if raw.get("reflection_value") or raw.get("reflected_value"):
        base += 0.05
    if raw.get("error") or raw.get("error_hint") or raw.get("response_error_hint"):
        base += 0.10
    if raw.get("match") or raw.get("matched_pattern"):
        base += 0.05
    if raw.get("bypass_header") or raw.get("injectable_header"):
        base += 0.05
    if raw.get("missing_idempotency_hint"):
        base += 0.03

    return clamp_confidence(base)


def _infer_exploitability(raw: Mapping[str, Any], confidence: float) -> Exploitability:
    if raw.get("confirmed") is True or raw.get("status") == "confirmed":
        return Exploitability.CONFIRMED
    if raw.get("verified") or raw.get("exploit_attempted"):
        return Exploitability.PROBABLE
    if confidence >= 0.75:
        return Exploitability.PROBABLE
    if confidence >= 0.45:
        return Exploitability.THEORETICAL
    if confidence >= 0.20:
        return Exploitability.THEORETICAL
    return Exploitability.UNKNOWN


# -- Bulk conversion -----------------------------------------------------------


def coerce_findings(
    rows: Iterable[Mapping[str, Any] | DetectionFinding],
    *,
    analyzer_key: str,
    phase: str,
) -> list[DetectionFinding]:
    """Convert a mixed iterable of dicts / DetectionFinding into typed findings.

    The original rows are preserved in `legacy` so reporting layers that
    expect raw dicts can still operate on the data.
    """

    out: list[DetectionFinding] = []
    for row in rows:
        if isinstance(row, DetectionFinding):
            out.append(row)
        elif isinstance(row, Mapping):
            out.append(from_dict(row, analyzer_key=analyzer_key, phase=phase))
    return out


def dicts_to_findings(
    rows: Iterable[Mapping[str, Any]],
    *,
    analyzer_key: str,
    phase: str,
) -> list[dict[str, Any]]:
    """Return plain dicts (legacy shape) but enriched with confidence, etc.

    Use this when the consumer is a reporting/UI layer that still wants the
    raw dict shape but benefits from the new fields.
    """

    return [f.to_dict() for f in coerce_findings(rows, analyzer_key=analyzer_key, phase=phase)]
