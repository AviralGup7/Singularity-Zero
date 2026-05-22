"""Remediation planner endpoints for the FastAPI dashboard."""

from __future__ import annotations

import json
import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request

from src.dashboard.fastapi.dependencies import get_queue_client, require_auth
from src.dashboard.remediation import suggest_for_finding

router = APIRouter(prefix="/api/remediation", tags=["Remediation"])

logger = logging.getLogger(__name__)


@router.get("/planner")
async def get_remediation_plan(
    request: Request,
    _auth: Any = Depends(require_auth),
    services: Any = Depends(get_queue_client),
) -> dict[str, Any]:
    """
    Generate a tactical remediation plan by grouping findings across all targets.
    """
    try:
        # 1. Fetch all findings across all targets
        # Note: In a production mesh, this might be a distributed query.
        # For now, we aggregate from the local finding store/targets.
        output_root = services.query.output_root
        all_findings = []

        if output_root.exists():
            for entry in sorted(output_root.iterdir(), key=lambda x: x.name.lower()):
                if not entry.is_dir() or entry.name.startswith("_"):
                    continue

                target_name = entry.name
                # Look for findings in all run directories
                run_dirs = [d for d in entry.iterdir() if d.is_dir() and (d / "run_summary.json").exists()]
                if not run_dirs:
                    # Fallback to check all subdirs
                    run_dirs = [d for d in entry.iterdir() if d.is_dir() and d.name != "checkpoints"]

                for run_dir in run_dirs:
                    findings_path = run_dir / "findings.json"
                    if findings_path.exists():
                        try:
                            findings = json.loads(findings_path.read_text(encoding="utf-8"))
                            if isinstance(findings, list):
                                for f in findings:
                                    if isinstance(f, dict):
                                        f_copy = dict(f)
                                        f_copy["target"] = target_name
                                        all_findings.append(f_copy)
                        except Exception:  # noqa: S110
                            pass

        # 2. Group findings by category (Tactical Fix Units)
        groups: dict[str, dict[str, Any]] = {}

        for finding in all_findings:
            category = finding.get("category", finding.get("type", "unknown")).lower()
            if category not in groups:
                # Generate remediation suggestion for the first finding in the group
                # (Assuming they share the same root cause pattern)
                suggestions = suggest_for_finding(finding)
                groups[category] = {
                    "category": category,
                    "title": category.replace("_", " ").title(),
                    "findings": [],
                    "suggestions": suggestions,
                    "severity": finding.get("severity", "low"),
                    "total_count": 0,
                    "targets": set(),
                }

            groups[category]["findings"].append(finding)
            groups[category]["total_count"] += 1
            groups[category]["targets"].add(finding["target"])

            # Elevate group severity if a critical finding is present
            if finding.get("severity") == "critical":
                groups[category]["severity"] = "critical"
            elif finding.get("severity") == "high" and groups[category]["severity"] not in (
                "critical",
                "high",
            ):
                groups[category]["severity"] = "high"

        # 3. Finalize plan output
        plan_units = []
        for cat, data in groups.items():
            data["targets"] = list(data["targets"])
            # Only include top 5 findings per unit to keep payload lean
            data["sample_findings"] = data["findings"][:5]
            del data["findings"]
            plan_units.append(data)

        # Sort by severity
        severity_map = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        plan_units.sort(key=lambda x: severity_map.get(x["severity"], 5))

        return {
            "status": "ok",
            "units": plan_units,
            "total_findings": len(all_findings),
            "total_units": len(plan_units),
        }
    except Exception as exc:
        logger.exception("Failed to generate remediation plan: %s", exc)
        raise HTTPException(status_code=500, detail="Remediation planning failed")
