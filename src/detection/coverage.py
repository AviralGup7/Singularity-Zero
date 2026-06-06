"""Engine referral contract.

Maps detection findings to the most appropriate exploitation engines so the
exploitation layer no longer has to rely on manual user mapping. The mapping
is intentionally conservative — a wrong referral wastes a probe cycle but a
missed referral leaves a vulnerability unvalidated.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from typing import Any

from src.detection.finding import DetectionFinding, Exploitability

logger = logging.getLogger(__name__)


# -- Engine catalogue ----------------------------------------------------------

EXPLOIT_ENGINE_KEYS: frozenset[str] = frozenset(
    {
        "httpexploitengine",
        "headerinjectionengine",
        "authbypassengine",
        "injectionengine",
        "webcachepoisonengine",
        "dnsrebindeengine",
        "subdomaintakeoverengine",
        "ssrfexploitationengine",
        "deserializationexploitationengine",
        "prototypepollutionengine",
        "sstiexploitationengine",
        "pathtraversalexploitationengine",
        "fileuploadexploitationengine",
        "raceconditionengine",
    }
)


# (indicator substring, engine key, priority, reason)
_INDICATOR_ENGINE_RULES: tuple[tuple[str, str, int, str], ...] = (
    ("xss", "injectionengine", 80, "XSS sink reached; replay with reflection/sink payload."),
    ("stored_xss", "injectionengine", 90, "Stored XSS — replay stored payload variant."),
    ("reflected_xss", "injectionengine", 85, "Reflected XSS — replay with same parameter."),
    ("dom_xss", "injectionengine", 75, "DOM XSS — needs headless browser, fallback to static sink replay."),
    ("open_redirect", "injectionengine", 70, "Open redirect — replay to confirm cross-host navigation."),
    ("ssrf", "ssrfexploitationengine", 90, "SSRF candidate — controlled callback probe."),
    ("server_side_request_forgery", "ssrfexploitationengine", 90, "SSRF candidate — OOB validation."),
    ("ssrf_candidate", "ssrfexploitationengine", 85, "SSRF candidate — controlled callback probe."),
    ("proxy_ssrf", "ssrfexploitationengine", 85, "Proxy SSRF — replay through the proxy."),
    ("sqli", "injectionengine", 90, "SQLi signal — replay with safe SQL payload."),
    ("sql_error", "injectionengine", 75, "SQL error leakage — replay to confirm blind or error-based."),
    ("sql_injection", "injectionengine", 90, "SQLi signal — replay with safe SQL payload."),
    ("command_injection", "injectionengine", 95, "Command injection — replay with safe command payload."),
    ("rce", "injectionengine", 95, "RCE signal — replay with safe payload."),
    ("remote_code_execution", "injectionengine", 95, "RCE signal — replay with safe payload."),
    ("ssti", "sstiexploitationengine", 90, "SSTI — replay with safe template expression."),
    ("template_injection", "sstiexploitationengine", 90, "SSTI — replay with safe template expression."),
    ("path_traversal", "pathtraversalexploitationengine", 90, "Path traversal — replay with safe file probe."),
    ("lfi", "pathtraversalexploitationengine", 85, "LFI — replay with safe file probe."),
    ("local_file_inclusion", "pathtraversalexploitationengine", 85, "LFI — replay with safe file probe."),
    ("file_upload", "fileuploadexploitationengine", 80, "File upload — replay with safe polyglot probe."),
    ("upload", "fileuploadexploitationengine", 80, "File upload — replay with safe polyglot probe."),
    ("deserialization", "deserializationexploitationengine", 90, "Deserialization — replay with safe gadget."),
    ("prototype_pollution", "prototypepollutionengine", 80, "Prototype pollution — replay with safe __proto__ probe."),
    ("race_condition", "raceconditionengine", 85, "Race condition — concurrent in-flight replay."),
    ("rate_limit", "raceconditionengine", 50, "Rate limit — concurrent burst replay (low priority)."),
    ("csrf", "authbypassengine", 60, "CSRF — replay with token omission/rotation."),
    ("cors", "authbypassengine", 55, "CORS — replay with origin reflection probe."),
    ("cache_poisoning", "webcachepoisonengine", 80, "Cache poisoning — replay with unkeyed header."),
    ("web_cache_poisoning", "webcachepoisonengine", 80, "Cache poisoning — replay with unkeyed header."),
    ("subdomain_takeover", "subdomaintakeoverengine", 90, "Subdomain takeover — confirm dangling record."),
    ("dns_rebind", "dnsrebindeengine", 80, "DNS rebinding — replay with rebind host."),
    ("header_injection", "headerinjectionengine", 90, "Header injection — replay with WAF bypass payload."),
    ("waf_bypass", "headerinjectionengine", 90, "WAF bypass candidate — replay with smuggling/H2 probe."),
    ("auth_bypass", "authbypassengine", 90, "Auth bypass — replay with method/role swap."),
    ("injection", "injectionengine", 70, "Generic injection — replay with safe payload."),
    ("idor", "injectionengine", 70, "IDOR — replay with IDOR mutation probe."),
    ("xxe", "deserializationexploitationengine", 80, "XXE — replay with safe external entity probe."),
    ("smuggling", "headerinjectionengine", 90, "HTTP smuggling — replay with CL.TE/TE.CL."),
)


def _cwe_to_engines(cwe_id: str | None) -> tuple[str, ...]:
    """Map a CWE ID to a tuple of exploitation engine keys."""

    if not cwe_id:
        return ()
    cwe = cwe_id.upper()
    table: dict[str, tuple[str, ...]] = {
        "CWE-79": ("injectionengine",),
        "CWE-89": ("injectionengine",),
        "CWE-78": ("injectionengine",),
        "CWE-94": ("injectionengine", "sstiexploitationengine"),
        "CWE-77": ("injectionengine",),
        "CWE-918": ("ssrfexploitationengine",),
        "CWE-601": ("injectionengine",),
        "CWE-22": ("pathtraversalexploitationengine",),
        "CWE-434": ("fileuploadexploitationengine",),
        "CWE-502": ("deserializationexploitationengine",),
        "CWE-1321": ("prototypepollutionengine",),
        "CWE-362": ("raceconditionengine",),
        "CWE-352": ("authbypassengine",),
        "CWE-942": ("authbypassengine",),
        "CWE-444": ("headerinjectionengine",),
        "CWE-93": ("headerinjectionengine",),
        "CWE-611": ("deserializationexploitationengine",),
    }
    return table.get(cwe, ())


def _url_hint_engines(url: str, indicator: str) -> tuple[str, ...]:
    """Last-resort engine guess based on URL/indicator lexical cues."""

    lowered_url = url.lower() if url else ""
    lowered_ind = indicator.lower() if indicator else ""
    if any(token in lowered_url for token in ("upload", "file", "media", "avatar")):
        return ("fileuploadexploitationengine",)
    if any(token in lowered_url for token in ("ssrf", "webhook", "fetch", "proxy")):
        return ("ssrfexploitationengine",)
    if any(token in lowered_url for token in ("template", "render", "view")):
        return ("sstiexploitationengine",)
    deserial_tokens = ("deserial", "pickle", "javaobj", "msgpack")
    if any(token in lowered_url for token in deserial_tokens) or any(
        token in lowered_ind for token in deserial_tokens
    ):
        return ("deserializationexploitationengine",)
    if any(token in lowered_url for token in ("checkout", "payment", "order", "redeem")):
        return ("raceconditionengine",)
    if any(token in lowered_ind for token in ("smuggling", "h2", "http2", "double-encoding")):
        return ("headerinjectionengine",)
    return ()


def recommend_engines(finding: DetectionFinding) -> tuple[str, ...]:
    """Resolve the tuple of recommended engines for a single finding.

    Resolution order (later layers refine but do not weaken earlier ones):
      1. Explicit `recommended_engines` set by the analyzer.
      2. Indicator substring rules.
      3. CWE ID heuristic.
      4. URL lexical hints.
    """

    explicit = tuple(finding.recommended_engines)
    indicator_matches: list[tuple[int, str]] = []
    indicator_lower = finding.indicator.lower()
    summary_lower = (finding.summary or "").lower()
    for needle, engine, priority, _reason in _INDICATOR_ENGINE_RULES:
        if needle in indicator_lower or needle in summary_lower:
            indicator_matches.append((priority, engine))
    indicator_matches.sort(key=lambda item: (-item[0], item[1]))
    indicator_engines = tuple(dict.fromkeys(engine for _, engine in indicator_matches))

    cwe_engines = _cwe_to_engines(finding.cwe_id)
    url_engines = _url_hint_engines(finding.url, finding.indicator)

    merged: list[str] = []
    for source in (explicit, indicator_engines, cwe_engines, url_engines):
        for engine in source:
            if engine in EXPLOIT_ENGINE_KEYS and engine not in merged:
                merged.append(engine)

    if not merged:
        merged.append("httpexploitengine")
    return tuple(merged)


def referral_reasons(finding: DetectionFinding) -> tuple[str, ...]:
    """Return a tuple of human-readable reasons for the engine recommendation."""

    reasons: list[str] = []
    indicator_lower = finding.indicator.lower()
    summary_lower = (finding.summary or "").lower()
    for needle, _engine, _priority, reason in _INDICATOR_ENGINE_RULES:
        if needle in indicator_lower or needle in summary_lower:
            if reason not in reasons:
                reasons.append(reason)
    if finding.cwe_id and _cwe_to_engines(finding.cwe_id):
        reasons.append(f"CWE mapping for {finding.cwe_id} selects matching engine.")
    if not reasons:
        reasons.append("Default HTTP exploit engine selected by fallback policy.")
    return tuple(reasons)


def apply_referral(finding: DetectionFinding) -> DetectionFinding:
    """Return a copy of the finding with the recommendation refreshed."""

    if not finding.recommended_engines:
        return DetectionFinding(
            finding_id=finding.finding_id,
            url=finding.url,
            indicator=finding.indicator,
            summary=finding.summary,
            severity=finding.severity,
            confidence=finding.confidence,
            exploitability=finding.exploitability,
            analyzer_key=finding.analyzer_key,
            phase=finding.phase,
            recommended_engines=recommend_engines(finding),
            evidence=finding.evidence,
            remediation_hint=finding.remediation_hint,
            cwe_id=finding.cwe_id,
            cve_id=finding.cve_id,
            tags=finding.tags,
            produced_at=finding.produced_at,
            metadata=finding.metadata,
            legacy=finding.legacy,
        )
    return finding


def is_actionable(finding: DetectionFinding, *, min_confidence: float = 0.45) -> bool:
    """A finding is actionable when it has at least one recommended engine
    and the confidence/exploitability combination justifies a probe.
    """

    if not finding.recommended_engines:
        return False
    if finding.confidence < min_confidence:
        return False
    if finding.exploitability == Exploitability.UNKNOWN and finding.confidence < 0.65:
        return False
    return True


def filter_actionable(
    findings: Iterable[DetectionFinding],
    *,
    min_confidence: float = 0.45,
) -> list[DetectionFinding]:
    return [f for f in findings if is_actionable(f, min_confidence=min_confidence)]


def group_by_engine(
    findings: Iterable[DetectionFinding],
) -> dict[str, list[DetectionFinding]]:
    """Group findings by their primary recommended engine."""

    grouped: dict[str, list[DetectionFinding]] = {}
    for finding in findings:
        for engine in finding.recommended_engines or ("httpexploitengine",):
            grouped.setdefault(engine, []).append(finding)
    return grouped


def referral_summary(findings: Iterable[DetectionFinding]) -> dict[str, Any]:
    """Build a small summary describing the recommended work distribution."""

    grouped = group_by_engine(findings)
    return {
        "total_findings": sum(len(items) for items in grouped.values()),
        "by_engine": {
            engine: {
                "count": len(items),
                "high_confidence": sum(1 for f in items if f.confidence >= 0.65),
                "confirmed": sum(
                    1 for f in items if f.exploitability == Exploitability.CONFIRMED
                ),
            }
            for engine, items in sorted(grouped.items())
        },
    }
