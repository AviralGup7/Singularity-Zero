import csv
import io
import json
from typing import Any


def flatten_finding_for_export(finding: dict[str, Any]) -> dict[str, Any]:
    evidence = finding.get("evidence") or {}
    evidence_summary = json.dumps(evidence, ensure_ascii=False) if evidence else ""

    mitre_attack = finding.get("mitre_attack") or []
    if isinstance(mitre_attack, list):
        mitre_attack = ", ".join(
            t.get("technique_id", "")
            for t in mitre_attack
            if isinstance(t, dict) and t.get("technique_id")
        )
    elif isinstance(mitre_attack, dict):
        mitre_attack = mitre_attack.get("technique_id", "")

    description = finding.get("description") or finding.get("explanation") or ""

    timestamp = (
        finding.get("timestamp")
        or finding.get("created_at")
        or finding.get("detected_at")
        or finding.get("generated_at_ist")
        or finding.get("generated_at_utc")
        or ""
    )

    return {
        "severity": finding.get("severity", ""),
        "category": finding.get("category", ""),
        "url": finding.get("url", ""),
        "title": finding.get("title", ""),
        "confidence": finding.get("confidence", ""),
        "score": finding.get("score", ""),
        "description": description,
        "evidence_summary": evidence_summary,
        "mitre_attack": mitre_attack,
        "timestamp": timestamp,
    }


_CSV_COLUMNS = [
    "severity",
    "category",
    "url",
    "title",
    "confidence",
    "score",
    "description",
    "evidence_summary",
    "mitre_attack",
    "timestamp",
]


def export_findings_csv(findings: list[dict[str, Any]]) -> str:
    if not findings:
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=_CSV_COLUMNS)
        writer.writeheader()
        return buf.getvalue()

    rows = [flatten_finding_for_export(f) for f in findings]
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=_CSV_COLUMNS)
    writer.writeheader()
    writer.writerows(rows)
    return buf.getvalue()


def export_findings_json(findings: list[dict[str, Any]]) -> str:
    rows = [flatten_finding_for_export(f) for f in findings]
    return json.dumps(rows, ensure_ascii=False, indent=2)
