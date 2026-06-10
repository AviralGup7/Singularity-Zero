"""Typed contracts for cross-module data exchange.

Defines the canonical shapes that each pipeline module produces and consumes
so drift between modules is caught at import-time rather than silently
falling back to ``dict.get(...)`` heuristics.

All TypedDicts are ``total=False`` by default so callers only need to
populate the fields they actually have; downstream readers should use
``.get()`` with sensible defaults.
"""

from __future__ import annotations

from typing import Any, TypedDict


# ---------------------------------------------------------------------------
# Recon → Analysis / Intelligence
# ---------------------------------------------------------------------------


class ReconExtras(TypedDict, total=False):
    """Structured container for optional recon stage outputs.

    The orchestrator stores this under ``ctx.recon_extras`` so downstream
    stages (analysis, enrichment, exploitation) can inspect it without
    having to re-invoke recon collectors.
    """

    origin_reprobe: dict[str, Any]
    port_scan: dict[str, Any] | None
    spa: dict[str, Any]
    headless_spa: dict[str, Any] | None
    graphql: list[dict[str, Any]] | None
    api_specs: list[dict[str, Any]] | None
    favicons: list[dict[str, Any]] | None
    asn: dict[str, Any]
    preview: list[dict[str, Any]] | None
    shodan_censys: dict[str, Any] | None
    archive_aggregated: dict[str, Any] | None
    waf_cdn: dict[str, Any]
    azure: dict[str, Any]


class ReconOutput(TypedDict, total=False):
    """Return contract for ``run_recon_layer`` / ``run_enhanced_recon_layer``.

    Every recon entry-point returns this shape (plus optional extra keys).
    Downstream orchestration should only read from this dict.
    """

    subdomains: set[str]
    live_hosts: set[str]
    urls: set[str]
    parameters: set[str]
    ranked_urls: list[dict[str, Any]]
    candidates: list[Any]  # list[ReconCandidate]
    wildcard_filter: dict[str, Any] | None
    extras: ReconExtras


# ---------------------------------------------------------------------------
# Detection → Analysis / Exploitation
# ---------------------------------------------------------------------------


class DetectionFindingDict(TypedDict, total=False):
    """Canonical dict shape emitted by detection handlers / plugins.

    Every detection plugin must emit dicts conforming to this shape.
    The ``indicator`` field is the primary key for engine referral;
    ``category`` is the vulnerability class for intel correlation.
    """

    url: str
    indicator: str
    category: str  # vulnerability class: sqli, ssrf, xss, idor, …
    summary: str
    severity: str  # info | low | medium | high | critical
    confidence: float
    analyzer_key: str
    phase: str
    recommended_engines: list[str]
    evidence: list[dict[str, Any]]
    cwe_id: str | None
    cve_id: str | None
    tags: list[str]
    finding_id: str
    # Legacy / optional fields that some plugins still emit
    title: str
    module: str
    score: float
    signals: list[str]
    mitre_attack: list[str]


class ResponseObservation(TypedDict, total=False):
    """Typed shape for HTTP response observations consumed by detection handlers.

    Every proactive probe should populate this shape before handing
    responses to detection handlers.  Handlers read specific keys and
    silently skip entries that lack the key they need.
    """

    url: str
    body: str | bytes | None
    body_text: str
    content_type: str
    status_code: int
    headers: dict[str, str]
    # CSRF / auth flow observations
    csrf_token_samples: list[str]
    csrf_tokens: dict[str, Any]
    pre_auth_token: str | None
    post_auth_token: str | None
    # Rate-limit observations
    rate_limit_samples: list[dict[str, Any]]
    rate_limit_observations: list[dict[str, Any]]
    # Race condition observations
    race_observation: dict[str, Any]
    # HPP observations
    hpp_observations: list[dict[str, Any]]
    # GraphQL observations
    graphql_introspection_observations: list[dict[str, Any]]
    # JWT observations
    jwt_observations: list[dict[str, Any]]
    jwt_claim_observations: list[dict[str, Any]]
    # WebSocket observations
    websocket_frame_observations: list[dict[str, Any]]


# ---------------------------------------------------------------------------
# Intelligence enrichment input / output
# ---------------------------------------------------------------------------


class IntelFindingInput(TypedDict, total=False):
    """Shape that ``ThreatIntelCorrelator.enrich_findings_with_intel`` reads.

    Intelligence modules should read *only* these keys from each finding
    dict.  If a key is absent, the enricher must use a safe default.
    """

    id: str
    url: str
    category: str  # vulnerability class (sqli, ssrf, xss, …)
    type: str  # fallback for category
    title: str
    severity: str
    confidence: float
    evidence: dict[str, Any]
    signals: list[str]
    # Existing intel state (may already be populated)
    cve_correlations: list[str]
    threat_intel: dict[str, Any]


class IntelFindingOutput(TypedDict, total=False):
    """Shape written back by ``ThreatIntelCorrelator.enrich_findings_with_intel``.

    The enricher mutates the finding dict and adds these keys.
    """

    cve_correlations: list[str]
    threat_intel: dict[str, Any]


# ---------------------------------------------------------------------------
# Severity model input
# ---------------------------------------------------------------------------


class SeverityModelInput(TypedDict, total=False):
    """Fields that ``CalibratedSeverityModel.predict`` reads from a finding.

    The severity model accepts a broad range of optional keys to handle
    findings from multiple sources (detection, nuclei, recon scoring).
    All fields are optional; the model falls back to safe defaults.
    """

    url: str
    host: str
    target_endpoint: str
    target_host: str
    category: str
    finding_category: str
    plugin_name: str
    module: str
    endpoint_type: str
    parameter_type: str
    decision: str
    finding_decision: str
    confidence: float
    finding_confidence: float
    severity: str
    finding_severity: str
    cvss_score: float
    score: float
    evidence: dict[str, Any]
    response_delta_score: float
    diff_score: float
    combined_signal: str
    signals: list[str]
    error: str
    error_hint: str
    response_error_hint: str
    match: str
    matched_pattern: str
    bypass_header: str
    injectable_header: str
    missing_idempotency_hint: bool
    asset_type: str
