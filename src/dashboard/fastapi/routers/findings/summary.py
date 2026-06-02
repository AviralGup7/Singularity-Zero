import json
import logging
from typing import Any

from fastapi import APIRouter, Depends, Query

from src.dashboard.fastapi.dependencies import get_queue_client, require_auth
from src.dashboard.fastapi.schemas import ErrorResponse, FindingsSummaryResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/findings", tags=["Findings"])


@router.get(
    "",
    response_model=FindingsSummaryResponse,
    responses={401: {"model": ErrorResponse}},
    summary="Get summary of all findings",
)
async def get_findings_summary(
    target: str | None = Query(None),
    _auth: Any = Depends(require_auth),
    services: Any = Depends(get_queue_client),
) -> dict[str, Any]:
    """Return a global summary of findings across all targets."""
    output_root = services.query.output_root
    total_findings = 0
    severity_totals = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    by_module: dict[str, int] = {}
    target_summaries: list[dict[str, Any]] = []
    targets_with_findings = 0
    total_targets = 0
    all_findings_list: list[dict[str, Any]] = []

    if not output_root.exists():
        return {
            "total_findings": 0,
            "severity_totals": severity_totals,
            "by_severity": severity_totals,
            "by_module": {},
            "findings": [],
            "targets": [],
            "targets_with_findings": 0,
            "total_targets": 0,
        }

    tenant_id = (_auth or {}).get("tenant_id", "default")
    from src.dashboard.fastapi.routers.targets import is_target_owned_by_tenant

    for entry in sorted(output_root.iterdir()):
        if not entry.is_dir() or entry.name.startswith("_"):
            continue
        if not is_target_owned_by_tenant(entry.name, tenant_id):
            continue

        if target and entry.name.lower() != target.lower():
            continue

        total_targets += 1
        target_finding_count = 0
        target_severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

        run_dirs = [d for d in entry.iterdir() if d.is_dir() and (d / "run_summary.json").exists()]
        if not run_dirs:
            run_dirs = [d for d in entry.iterdir() if d.is_dir() and d.name != "checkpoints"]

        for run_dir in run_dirs:
            findings_path = run_dir / "findings.json"
            if findings_path.exists():
                try:
                    findings = json.loads(findings_path.read_text(encoding="utf-8"))
                    if isinstance(findings, list):
                        for f in findings:
                            sev = str(f.get("severity", "info")).lower()
                            if sev in severity_totals:
                                severity_totals[sev] += 1
                                target_severity_counts[sev] += 1

                            mod = str(f.get("module", "unknown"))
                            by_module[mod] = by_module.get(mod, 0) + 1

                            total_findings += 1
                            target_finding_count += 1

                            if len(all_findings_list) < 50:
                                all_findings_list.append(f)
                except Exception:  # noqa: S112
                    continue

        if target_finding_count > 0:
            targets_with_findings += 1
            target_summaries.append(
                {
                    "name": entry.name,
                    "finding_count": target_finding_count,
                    "severity_counts": target_severity_counts,
                }
            )

    return {
        "total_findings": total_findings,
        "severity_totals": severity_totals,
        "by_severity": severity_totals,
        "by_module": by_module,
        "findings": all_findings_list,
        "targets": target_summaries,
        "targets_with_findings": targets_with_findings,
        "total_targets": total_targets,
    }
