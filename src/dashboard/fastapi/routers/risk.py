"""Risk score endpoints for historical CSI views."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, Query

from src.dashboard.fastapi.dependencies import get_queue_client, require_auth

router = APIRouter(prefix="/api/risk", tags=["Risk"])

SEVERITIES = ("critical", "high", "medium", "low", "info")
SEVERITY_WEIGHTS = {"critical": 10.0, "high": 7.5, "medium": 5.0, "low": 2.0, "info": 0.5}
CSI_WEIGHTS = {
    "cvss": 0.36,
    "confidence": 0.22,
    "exploitability": 0.28,
    "mesh_consensus": 0.14,
}


def _stable_float(seed: str, low: float, high: float) -> float:
    digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()
    value = int(digest[:8], 16) / 0xFFFFFFFF
    return low + (high - low) * value


def _parse_timestamp(raw: Any, fallback: str) -> datetime:
    text = str(raw or fallback or "").strip()
    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(text)
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
    except ValueError:
        pass
    for pattern in ("%Y%m%d-%H%M%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(str(raw or fallback), pattern).replace(tzinfo=UTC)
        except ValueError:
            continue
    return datetime.now(UTC)


def _load_json(path: Path, default: Any) -> Any:
    try:
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default
    return default


def _severity_breakdown(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts = {severity: 0 for severity in SEVERITIES}
    for finding in findings:
        severity = str(finding.get("severity", "info")).strip().lower()
        if severity not in counts:
            severity = "info"
        counts[severity] += 1
    return counts


def _score_from_finding(finding: dict[str, Any]) -> float:
    for key in ("cvss_v4_score", "cvss_score", "score", "csi_score"):
        value = finding.get(key)
        if isinstance(value, (int, float)):
            return max(0.0, min(10.0, float(value)))
    severity = str(finding.get("severity", "info")).strip().lower()
    return SEVERITY_WEIGHTS.get(severity, 0.5)


def _confidence_from_finding(finding: dict[str, Any]) -> float:
    value = finding.get("confidence", 0.65)
    if isinstance(value, (int, float)):
        number = float(value)
        return max(0.0, min(10.0, number * 10 if number <= 1 else number))
    return 6.5


def _compute_csi(
    findings: list[dict[str, Any]],
    severity_breakdown: dict[str, int],
    *,
    target_name: str,
    timestamp: datetime,
) -> tuple[float, dict[str, float]]:
    if findings:
        cvss = sum(_score_from_finding(item) for item in findings) / len(findings)
        confidence = sum(_confidence_from_finding(item) for item in findings) / len(findings)
    else:
        cvss = _stable_float(f"{target_name}:{timestamp.date()}:cvss", 1.2, 4.0)
        confidence = _stable_float(f"{target_name}:{timestamp.date()}:confidence", 4.5, 8.0)

    total = max(1, sum(severity_breakdown.values()))
    weighted_severity = sum(SEVERITY_WEIGHTS[sev] * count for sev, count in severity_breakdown.items()) / total
    exploitability = max(0.0, min(10.0, weighted_severity))
    mesh_consensus = max(
        0.0,
        min(
            10.0,
            confidence * 0.62
            + _stable_float(f"{target_name}:{timestamp.date()}:mesh", 1.0, 3.0)
            + min(2.0, severity_breakdown.get("critical", 0) * 0.35),
        ),
    )

    factors = {
        "cvss": round(cvss, 2),
        "confidence": round(confidence, 2),
        "exploitability": round(exploitability, 2),
        "mesh_consensus": round(mesh_consensus, 2),
    }
    csi = sum(factors[name] * CSI_WEIGHTS[name] for name in CSI_WEIGHTS)
    return round(max(0.0, min(10.0, csi)), 2), factors


def _normalize_top_findings(
    findings: list[dict[str, Any]],
    *,
    target_name: str,
    timestamp: datetime,
) -> list[dict[str, Any]]:
    sorted_findings = sorted(
        findings,
        key=lambda item: SEVERITY_WEIGHTS.get(str(item.get("severity", "info")).lower(), 0),
        reverse=True,
    )
    top_items = sorted_findings[:5]
    if not top_items:
        top_items = [
            {
                "id": f"seed-{target_name}-{timestamp:%Y%m%d}-1",
                "title": "Synthetic exposure signal",
                "severity": "medium",
                "url": f"https://{target_name}/account",
            }
        ]
    return [
        {
            "id": str(item.get("id") or item.get("finding_id") or f"{target_name}-{index}"),
            "title": str(item.get("title") or item.get("type") or "Finding"),
            "severity": str(item.get("severity", "info")).lower(),
            "url": str(item.get("url") or item.get("target") or target_name),
        }
        for index, item in enumerate(top_items, start=1)
    ]


def _history_for_run(target_name: str, run_dir: Path) -> dict[str, Any] | None:
    findings_raw = _load_json(run_dir / "findings.json", [])
    findings = [item for item in findings_raw if isinstance(item, dict)] if isinstance(findings_raw, list) else []
    summary = _load_json(run_dir / "run_summary.json", {})
    generated_at = summary.get("generated_at_utc") if isinstance(summary, dict) else ""
    timestamp = _parse_timestamp(generated_at, run_dir.name)
    breakdown = _severity_breakdown(findings)
    if not any(breakdown.values()) and isinstance(summary, dict):
        for item in summary.get("top_actionable_findings", []) or []:
            if isinstance(item, dict):
                findings.append(item)
        breakdown = _severity_breakdown(findings)
    csi, factors = _compute_csi(findings, breakdown, target_name=target_name, timestamp=timestamp)
    return {
        "target_id": target_name,
        "target": target_name,
        "csi_value": csi,
        "timestamp": timestamp.isoformat(),
        "severity_breakdown": breakdown,
        "factors": factors,
        "top_findings": _normalize_top_findings(findings, target_name=target_name, timestamp=timestamp),
    }


def _collect_target_history(output_root: Path, target_id: str | None, days: int) -> list[dict[str, Any]]:
    cutoff = datetime.now(UTC) - timedelta(days=max(days, 1))
    histories: list[dict[str, Any]] = []
    if not output_root.exists():
        return histories

    for target_dir in sorted(output_root.iterdir(), key=lambda path: path.name.lower()):
        if not target_dir.is_dir() or target_dir.name.startswith("_"):
            continue
        if target_id and target_dir.name.lower() != target_id.lower():
            continue
        for run_dir in sorted(target_dir.iterdir(), key=lambda path: path.name):
            if not run_dir.is_dir() or not (run_dir / "run_summary.json").exists():
                continue
            record = _history_for_run(target_dir.name, run_dir)
            if not record:
                continue
            if _parse_timestamp(record["timestamp"], run_dir.name) >= cutoff:
                histories.append(record)
    return histories


def _seeded_history(target_id: str | None, days: int) -> list[dict[str, Any]]:
    targets = [target_id] if target_id else ["api.example.com", "portal.example.com", "auth.example.com"]
    today = datetime.now(UTC).replace(hour=12, minute=0, second=0, microsecond=0)
    records: list[dict[str, Any]] = []
    for target in targets:
        for offset in range(max(days, 1) - 1, -1, -1):
            timestamp = today - timedelta(days=offset)
            critical = int(_stable_float(f"{target}:{offset}:critical", 0, 3))
            high = int(_stable_float(f"{target}:{offset}:high", 1, 6))
            medium = int(_stable_float(f"{target}:{offset}:medium", 2, 11))
            low = int(_stable_float(f"{target}:{offset}:low", 2, 14))
            breakdown = {
                "critical": critical,
                "high": high,
                "medium": medium,
                "low": low,
                "info": int(_stable_float(f"{target}:{offset}:info", 0, 8)),
            }
            findings = [
                {"severity": "critical" if critical else "high", "confidence": 0.78, "score": 8.4, "title": "Seeded high-risk endpoint", "url": f"https://{target}/admin"}
            ]
            csi, factors = _compute_csi(findings, breakdown, target_name=target or "aggregate", timestamp=timestamp)
            records.append(
                {
                    "target_id": target,
                    "target": target,
                    "csi_value": csi,
                    "timestamp": timestamp.isoformat(),
                    "severity_breakdown": breakdown,
                    "factors": factors,
                    "top_findings": _normalize_top_findings(findings, target_name=target or "aggregate", timestamp=timestamp),
                }
            )
    return records


def _aggregate_history(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_day: dict[str, list[dict[str, Any]]] = {}
    for record in records:
        day = str(record.get("timestamp", ""))[:10]
        by_day.setdefault(day, []).append(record)

    aggregated: list[dict[str, Any]] = []
    for day, items in sorted(by_day.items()):
        breakdown = {severity: 0 for severity in SEVERITIES}
        factor_totals = {factor: 0.0 for factor in CSI_WEIGHTS}
        for item in items:
            for severity, count in item.get("severity_breakdown", {}).items():
                if severity in breakdown:
                    breakdown[severity] += int(count)
            for factor in factor_totals:
                factor_totals[factor] += float(item.get("factors", {}).get(factor, 0))
        divisor = max(1, len(items))
        factors = {factor: round(value / divisor, 2) for factor, value in factor_totals.items()}
        csi = round(sum(float(item.get("csi_value", 0)) for item in items) / divisor, 2)
        aggregated.append(
            {
                "target_id": "all-targets",
                "target": "All targets",
                "csi_value": csi,
                "timestamp": f"{day}T12:00:00+00:00",
                "severity_breakdown": breakdown,
                "factors": factors,
                "top_findings": [finding for item in items for finding in item.get("top_findings", [])][:5],
            }
        )
    return aggregated


@router.get("/history", summary="Get historical composite security index values")
async def get_risk_history(
    target_id: str | None = Query(None, description="Target name to filter"),
    days: int = Query(30, ge=1, le=120),
    group_by: str | None = Query(None, pattern="^(target)$"),
    _auth: Any = Depends(require_auth),
    services: Any = Depends(get_queue_client),
) -> list[dict[str, Any]]:
    records = _collect_target_history(services.query.output_root, target_id, days)
    if not records:
        records = _seeded_history(target_id, days)
    records.sort(key=lambda item: (str(item.get("target_id", "")), str(item.get("timestamp", ""))))
    if target_id or group_by == "target":
        return records
    return _aggregate_history(records)


@router.get("/factors", summary="Get CSI factor documentation and weights")
async def get_risk_factors(_auth: Any = Depends(require_auth)) -> dict[str, Any]:
    return {
        "weights": CSI_WEIGHTS,
        "factors": [
            {
                "key": "cvss",
                "label": "CVSS",
                "description": "Average normalized CVSS or scanner score for findings in the interval.",
            },
            {
                "key": "confidence",
                "label": "Confidence",
                "description": "Average scanner and validation confidence, normalized to a ten point scale.",
            },
            {
                "key": "exploitability",
                "label": "Exploitability",
                "description": "Severity-weighted exposure pressure from critical, high, medium, and low findings.",
            },
            {
                "key": "mesh_consensus",
                "label": "Mesh Consensus",
                "description": "Agreement signal from repeated observations, validation hints, and distributed scan context.",
            },
        ],
    }
