"""Export pipeline findings to a SARIF document readable by Burp Suite."""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path
from typing import Any, Iterable


logger = logging.getLogger(__name__)


def _coerce_finding_attributes(finding: Any) -> dict[str, Any]:
    if hasattr(finding, "__dataclass_fields__"):
        return {
            "category": getattr(finding, "category", ""),
            "title": getattr(finding, "title", ""),
            "url": getattr(finding, "url", ""),
            "severity": getattr(finding, "severity", "info"),
            "confidence": float(getattr(finding, "confidence", 0.0)),
            "evidence": getattr(finding, "evidence", {}) or {},
            "signals": getattr(finding, "signals", []) or [],
        }
    if isinstance(finding, dict):
        return {
            "category": finding.get("category", ""),
            "title": finding.get("title") or finding.get("category", ""),
            "url": finding.get("url", ""),
            "severity": finding.get("severity", "info"),
            "confidence": float(finding.get("confidence", 0.0)),
            "evidence": finding.get("evidence", {}) or {},
            "signals": finding.get("signals", []) or [],
        }
    return {}


def export_to_burp_sarif(findings: Any, output_path: str) -> Path:
    """Write a SARIF 2.1.0 document for Burp Suite's SARIF importer."""
    normalised: list[dict[str, Any]] = []
    if hasattr(findings, "__iter__") and not hasattr(findings, "items"):
        for item in findings:
            normalised.append(_coerce_finding_attributes(item))
    else:
        normalised.append(_coerce_finding_attributes(findings))

    scans = []
    for finding in normalised:
        rule_id = _rule_id_for(finding)
        result = {
            "ruleId": rule_id,
            "level": _level_for(finding.get("severity", "info")),
            "message": {"text": finding.get("title", "")},
            "locations": _locations_for(finding.get("url", "")),
            "properties": {
                "confidence": finding.get("confidence", 0.0),
                "signals": finding.get("signals", []),
            },
        }
        scans.append(result)

    run = {
        "tool": {
            "driver": {
                "name": "cyber-security-test-pipeline",
                "version": "2.0.0",
                "informationUri": "https://github.com/kilo-ai/kilocode",
            }
        },
        "results": scans,
    }

    sarif = {
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [run],
    }

    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(sarif, indent=2, default=str), encoding="utf-8")
    logger.info("Wrote Burp SARIF export to %s", out)
    return out


def _rule_id_for(finding: dict[str, Any]) -> str:
    category = str(finding.get("category", "")).strip() or "external"
    severity = str(finding.get("severity", "")).strip() or "info"
    suffix = hashlib.sha1(finding.get("url", "").encode("utf-8")).hexdigest()[:8]
    return f"burp/{category}/{severity}/{suffix}"


def _level_for(severity: str) -> str:
    mapping = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "info": "note",
    }
    return mapping.get(str(severity or "info").lower(), "note")


def _locations_for(url: str) -> list[dict[str, Any]]:
    if not url:
        return [{"physicalLocation": {"artifactLocation": {"uri": "unknown"}}}]
    return [
        {
            "physicalLocation": {
                "artifactLocation": {
                    "uri": url,
                    "uriBaseId": "%SRCROOT%",
                }
            }
        }
    ]
