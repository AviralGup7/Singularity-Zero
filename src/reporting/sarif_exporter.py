"""SARIF 2.1 exporter for reportable findings.

Converts the pipeline's internal ``reportable_findings`` representation
into a SARIF 2.1.0 document so CI providers (GitHub Code Scanning,
GitLab, Azure DevOps, IDE plugins) can ingest findings as native code
scan alerts.

The exporter is deliberately tolerant: it never raises on a single
malformed finding.  Findings that fail to normalise are recorded in
``run.logs`` with their offending payload truncated, and the rest of
the document is emitted as-is.  This keeps partial runs useful to CI
consumers even when a probe produced garbage.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

SARIF_SCHEMA = "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"

SEVERITY_TO_SARIF_LEVEL: dict[str, str] = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
    "informational": "note",
}

_SEVERITY_TO_CVSS: dict[str, float] = {
    "critical": 9.5,
    "high": 7.5,
    "medium": 5.0,
    "low": 3.0,
    "info": 1.0,
}

_WEB_PATH_SCHEMES = {"http", "https"}


def _coerce_str(value: Any, default: str = "") -> str:
    if value is None:
        return default
    if isinstance(value, str):
        return value
    return str(value)


def _is_false_positive(finding: Mapping[str, Any]) -> bool:
    lifecycle = str(finding.get("lifecycle_state", "")).strip().lower()
    if lifecycle in {"false_positive", "fp", "false-positive"}:
        return True
    if str(finding.get("status", "")).lower() == "false_positive":
        return True
    if finding.get("falsePositive") is True:
        return True
    decision = finding.get("ai_triage_decision")
    return isinstance(decision, str) and decision.upper() == "FP"


def _derive_artifact_location(url: str) -> tuple[str, str | None]:
    """Return ``(uri, base_id)`` suitable for SARIF ``artifactLocation``.

    For HTTP/HTTPS URLs we return the URL itself as ``uri`` (SARIF allows
    any URI in ``artifactLocation.uri``) and the URL's host as
    ``uriBaseId`` so consumers can resolve it to a local path if a
    ``uriBaseId`` mapping is configured at the tool level.
    """
    parsed = urlparse(url)
    if parsed.scheme in _WEB_PATH_SCHEMES:
        host = parsed.netloc
        return url, host or None
    return url, None


def _fingerprint(finding: Mapping[str, Any], *, url: str, rule_id: str) -> str:
    """Stable, deterministic identifier for a finding across runs.

    CI providers (notably GitHub) dedupe on partialFingerprints, so the
    same logical finding must produce the same hash on every run.
    """
    category = _coerce_str(finding.get("category"), "unknown")
    title = _coerce_str(finding.get("title"), "")
    h = hashlib.sha256()
    h.update(f"{rule_id}|{url}|{category}|{title}".encode())
    return h.hexdigest()[:32]


def _short_message(finding: Mapping[str, Any]) -> str:
    title = _coerce_str(finding.get("title"))
    category = _coerce_str(finding.get("category"), "finding")
    if title:
        return f"{category}: {title}"[:200]
    return category[:200]


def _full_message(finding: Mapping[str, Any]) -> str:
    parts: list[str] = []
    if finding.get("description"):
        parts.append(_coerce_str(finding["description"]))
    if finding.get("evidence"):
        parts.append(f"Evidence: {finding['evidence']}")
    if finding.get("remediation"):
        parts.append(f"Remediation: {finding['remediation']}")
    return "\n\n".join(parts)[:4000]


@dataclass(frozen=True)
class SarifExportResult:
    """Result of an export.

    ``document`` is the SARIF JSON-serializable dict.  ``dropped`` is
    the number of findings skipped because they could not be normalised
    (recorded in ``run.logs`` instead so the document always parses).
    """

    document: dict[str, Any]
    dropped: int
    total: int


_RULE_ID_CLEAN_RE = re.compile(r"[^a-zA-Z0-9_.:/=+-]")


def _rule_id(finding: Mapping[str, Any]) -> str:
    raw = _coerce_str(finding.get("rule_id")) or _coerce_str(
        finding.get("vuln_type")
    ) or _coerce_str(finding.get("category"), "unknown-finding")
    cleaned = _RULE_ID_CLEAN_RE.sub("-", raw).strip("-")
    return cleaned or "unknown-finding"


def export_findings_to_sarif(
    findings: Sequence[Mapping[str, Any]],
    *,
    tool_name: str = "cyber-security-test-pipeline",
    tool_version: str = "2.0.0",
    info_uri: str = "https://example.invalid/cyber-security-test-pipeline",
    include_false_positives: bool = False,
) -> SarifExportResult:
    """Convert ``findings`` to a SARIF 2.1.0 document.

    Args:
        findings: Normalized reportable-finding dicts.
        tool_name: Value of ``tool.driver.name`` in the SARIF document.
        tool_version: Value of ``tool.driver.version``.
        info_uri: Value of ``tool.driver.informationUri``.
        include_false_positives: When ``False`` (default) findings marked
            as FP by the AI triage or by lifecycle_state are filtered
            out so CI doesn't raise alerts on known FPs.
    """
    rules_by_id: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    logs: list[dict[str, Any]] = []
    dropped = 0

    visible = (
        list(findings)
        if include_false_positives
        else [f for f in findings if not _is_false_positive(f)]
    )

    for finding in visible:
        try:
            url = _coerce_str(finding.get("url")) or "<unknown>"
            rule_id = _rule_id(finding)
            severity = _coerce_str(finding.get("severity"), "low").lower()
            level = SEVERITY_TO_SARIF_LEVEL.get(severity, "note")
            uri, uri_base_id = _derive_artifact_location(url)

            if rule_id not in rules_by_id:
                rules_by_id[rule_id] = {
                    "id": rule_id,
                    "name": rule_id,
                    "shortDescription": {
                        "text": _coerce_str(finding.get("category"), rule_id)[:200]
                    },
                    "fullDescription": {
                        "text": _coerce_str(finding.get("description")) or rule_id
                    },
                    "helpUri": info_uri,
                    "defaultConfiguration": {"level": level},
                    "properties": {
                        "security-severity": f"{_SEVERITY_TO_CVSS.get(severity, 3.0):.1f}",
                        "tags": [
                            "security",
                            f"severity:{severity}",
                        ],
                    },
                }

            properties: dict[str, Any] = {
                "category": _coerce_str(finding.get("category")),
                "severity": severity,
                "confidence": finding.get("confidence"),
                "score": finding.get("score"),
                "cwe": finding.get("cwe_id") or finding.get("cwe"),
            }
            if finding.get("ai_triage_decision"):
                properties["ai_triage_decision"] = _coerce_str(
                    finding["ai_triage_decision"]
                )
            if finding.get("ai_confidence_score") is not None:
                properties["ai_confidence_score"] = finding["ai_confidence_score"]

            result: dict[str, Any] = {
                "ruleId": rule_id,
                "level": level,
                "message": {
                    "text": _short_message(finding),
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": uri,
                                **({"uriBaseId": uri_base_id} if uri_base_id else {}),
                            }
                        }
                    }
                ],
                "partialFingerprints": {
                    "primary": _fingerprint(finding, url=url, rule_id=rule_id)
                },
                "properties": {k: v for k, v in properties.items() if v is not None},
            }
            full = _full_message(finding)
            if full:
                result["message"]["text"] = f"{_short_message(finding)}\n\n{full}"
            results.append(result)
        except Exception as exc:  # noqa: BLE001
            dropped += 1
            logs.append(
                {
                    "level": "warning",
                    "message": {
                        "text": f"Dropped malformed finding: {exc!s} "
                        f"(payload truncated to 200 chars: "
                        f"{str(finding)[:200]!r})"
                    },
                }
            )

    document: dict[str, Any] = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "version": tool_version,
                        "informationUri": info_uri,
                        "rules": list(rules_by_id.values()),
                        "supportedTaxonomies": [
                            {"name": "CWE", "shortDescription": {"text": "CWE"}}
                        ],
                    }
                },
                "originalUriBaseIds": {
                    **{
                        host: {"uri": f"https://{host}/"}
                        for host in {
                            urlparse(_coerce_str(r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"])).netloc
                            for r in results
                            if urlparse(
                                _coerce_str(
                                    r["locations"][0]["physicalLocation"][
                                        "artifactLocation"
                                    ]["uri"]
                                )
                            ).scheme
                            in _WEB_PATH_SCHEMES
                        }
                    }
                },
                "results": results,
                **({"logs": logs} if logs else {}),
            }
        ],
    }
    # Clean up the originalUriBaseIds so empty mappings don't pollute the
    # document — SARIF tooling rejects unknown uriBaseIds.
    if not document["runs"][0]["originalUriBaseIds"]:
        del document["runs"][0]["originalUriBaseIds"]

    return SarifExportResult(document=document, dropped=dropped, total=len(visible))


def merge_sarif_documents(documents: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Merge multiple SARIF documents into one.

    Used by multi-target reports and the replay verifier to combine
    per-run SARIF output into a single uploadable artifact.
    """
    merged_rules: dict[str, dict[str, Any]] = {}
    merged_results: list[dict[str, Any]] = []
    merged_logs: list[dict[str, Any]] = []
    tool_drivers: list[dict[str, Any]] = []

    for doc in documents:
        for run in doc.get("runs", []):
            driver = run.get("tool", {}).get("driver", {})
            tool_drivers.append(driver)
            for rule in driver.get("rules", []) or []:
                rid = rule.get("id")
                if rid and rid not in merged_rules:
                    merged_rules[rid] = rule
            merged_results.extend(run.get("results", []) or [])
            merged_logs.extend(run.get("logs", []) or [])

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        **(tool_drivers[0] if tool_drivers else {}),
                        "rules": list(merged_rules.values()),
                    }
                },
                "results": merged_results,
                **({"logs": merged_logs} if merged_logs else {}),
            }
        ],
    }


def sarif_to_finding(sarif_result: Mapping[str, Any]) -> dict[str, Any]:
    """Convert a single SARIF result into the internal finding shape used by
    the platform exporters (HackerOne, Bugcrowd, Intigriti, Synack).

    The internal shape is intentionally minimal — the platform exporters
    enrich it with the structured fields each platform's API requires.
    """
    message = sarif_result.get("message", {})
    text = message.get("text", "") if isinstance(message, Mapping) else str(message)
    locations = sarif_result.get("locations", []) or []
    url = ""
    if locations:
        loc = locations[0]
        phys = loc.get("physicalLocation", {}) if isinstance(loc, Mapping) else {}
        art = phys.get("artifactLocation", {}) if isinstance(phys, Mapping) else {}
        url = str(art.get("uri") or "")
    properties = sarif_result.get("properties", {}) or {}
    rule_id = str(sarif_result.get("ruleId", "unknown"))
    severity = str(properties.get("severity") or sarif_result.get("level") or "medium").lower()
    return {
        "id": str(properties.get("finding_id") or sarif_result.get("partialFingerprints", {}).get("primary", "")),
        "title": text.split("\n", 1)[0][:240] if text else rule_id,
        "description": text,
        "severity": severity,
        "type": str(properties.get("category") or rule_id),
        "url": url,
        "host": "",
        "target": url,
        "cwe": properties.get("cwe"),
        "cve": properties.get("cve"),
        "cvss_score": properties.get("cvss"),
        "confidence": properties.get("confidence", 0.5),
        "rule_id": rule_id,
        "properties": dict(properties),
    }


def sarif_to_platform_report(
    sarif_document: Mapping[str, Any],
    platform: str = "hackerone",
) -> list[dict[str, Any]]:
    """Bridge a SARIF document to a list of platform-native report payloads.

    Each entry in the returned list is the exact body the platform's
    submission API expects (HackerOne: ``POST /v1/reports`` shape, etc.).
    The platform's own exporter (``HackerOneExporter`` etc.) is responsible
    for rendering the markdown; this function only extracts the
    structured fields.

    Supported platforms: ``hackerone``, ``bugcrowd``, ``intigriti``,
    ``synack``. Unknown platforms return the raw finding dicts.
    """
    platform = platform.lower()
    findings: list[dict[str, Any]] = []
    for run in sarif_document.get("runs", []) or []:
        for result in run.get("results", []) or []:
            findings.append(sarif_to_finding(result))

    if platform not in {"hackerone", "bugcrowd", "intigriti", "synack"}:
        return findings

    shaped: list[dict[str, Any]] = []
    for f in findings:
        if platform == "hackerone":
            shaped.append({
                "data": {
                    "type": "report",
                    "attributes": {
                        "title": f.get("title", "Security finding")[:140],
                        "severity_rating": _h1_severity(f.get("severity")),
                        "vulnerability_information": f.get("description", ""),
                    },
                }
            })
        elif platform == "bugcrowd":
            shaped.append({
                "title": f.get("title", "Security finding")[:140],
                "description": f.get("description", ""),
                "severity": int(_bugcrowd_payout(f.get("severity"))),
                "priority": _bugcrowd_priority(f.get("severity")),
                "category": f.get("type", "other"),
            })
        elif platform == "intigriti":
            shaped.append({
                "title": f.get("title", "Security finding")[:140],
                "description": f.get("description", ""),
                "severity": _intigriti_severity(f.get("severity")),
                "weakness": {"id": _intigriti_weakness_id(f.get("type"))},
            })
        else:  # synack
            shaped.append({
                "title": f.get("title", "Security finding")[:200],
                "description": f.get("description", ""),
                "severity": _synack_severity(f.get("severity")),
                "vulnerability_category": f.get("type", "other"),
            })
    return shaped


def _h1_severity(sev: Any) -> str:
    s = str(sev or "").lower()
    return s if s in {"critical", "high", "medium", "low", "none"} else "none"


def _bugcrowd_payout(sev: Any) -> float:
    return {
        "critical": 5.0,
        "high": 4.0,
        "medium": 3.0,
        "low": 2.0,
    }.get(str(sev or "").lower(), 1.0)


def _bugcrowd_priority(sev: Any) -> int:
    return {
        "critical": 1,
        "high": 2,
        "medium": 3,
        "low": 4,
    }.get(str(sev or "").lower(), 5)


def _intigriti_severity(sev: Any) -> int:
    return {
        "critical": 5,
        "high": 4,
        "medium": 3,
        "low": 2,
    }.get(str(sev or "").lower(), 1)


def _intigriti_weakness_id(finding_type: Any) -> str:
    t = str(finding_type or "").lower()
    if "xss" in t:
        return "xss"
    if "sql" in t:
        return "sqli"
    if "ssrf" in t:
        return "server_side_request_forgery"
    if "rce" in t or "command" in t:
        return "rce"
    if "auth" in t or "broken" in t:
        return "broken_authentication"
    if "idor" in t or "bola" in t:
        return "idor"
    return "other"


def _synack_severity(sev: Any) -> str:
    return {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
    }.get(str(sev or "").lower(), "informational")
