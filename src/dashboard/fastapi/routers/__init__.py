"""Router aggregation for the FastAPI dashboard."""

import logging
from typing import Any, cast

from fastapi import APIRouter

logger = logging.getLogger(__name__)

from .access_logs import router as access_logs_router
from .assignments import router as assignments_router
from .audit import router as audit_router
from .bloom import router as bloom_router
from .cache import router as cache_router
from .cockpit import router as cockpit_router
from .compliance import router as compliance_router
from .defaults import router as defaults_router
from .evasion import router as evasion_router
from .evidence_custody import router as evidence_custody_router
from .export import router as export_router
from .findings import router as findings_router
from .forensics_trace import router as forensics_trace_router
from .gap_analysis import router as gap_analysis_router
from .health import router as health_router
from .jobs import router as jobs_router
from .launcher import router as launcher_router
from .learning import router as learning_router
from .mesh import router as mesh_router
from .notes import router as notes_router
from .notifications import router as notifications_router
from .projects import router as projects_router
from .registry import router as registry_router
from .remediated import router as remediated_router
from .remediation import router as remediation_router
from .replay import router as replay_router
from .reports import router as reports_router
from .risk import router as risk_router
from .risk_domain import router as risk_domain_router
from .security import router as security_router
from .self_healing import router as self_healing_router
from .targets import router as targets_router
from .tracing import router as tracing_router
from .triage import router as triage_router
from .webhooks import router as webhooks_router

imports_router: Any = None
try:
    from .imports import router as _imports_router

    imports_router = _imports_router
except Exception as exc:
    logger.warning("Imports router disabled: %s", exc)

api_router = APIRouter()

api_router.include_router(health_router, tags=["Health"])
api_router.include_router(remediated_router, tags=["Remediation Verification"])
api_router.include_router(self_healing_router, tags=["Self-Healing"])
api_router.include_router(audit_router, tags=["Audit"])
api_router.include_router(bloom_router, tags=["Bloom"])
api_router.include_router(cockpit_router, tags=["Cockpit"])
api_router.include_router(jobs_router, tags=["Jobs"])
api_router.include_router(learning_router, tags=["Learning"])
api_router.include_router(mesh_router, tags=["Mesh"])
api_router.include_router(targets_router, tags=["Targets"])
api_router.include_router(findings_router, tags=["Findings"])
api_router.include_router(notifications_router, tags=["Notifications"])
api_router.include_router(cache_router, tags=["Cache"])
api_router.include_router(defaults_router, tags=["Defaults"])
api_router.include_router(notes_router, tags=["Notes"])
api_router.include_router(export_router, tags=["Export"])
api_router.include_router(replay_router, tags=["Replay"])
api_router.include_router(risk_router, tags=["Risk"])
api_router.include_router(risk_domain_router, tags=["Risk Domain"])
api_router.include_router(remediation_router, tags=["Remediation"])
api_router.include_router(reports_router, tags=["Reports"])
api_router.include_router(registry_router, tags=["Registry"])
api_router.include_router(projects_router, tags=["Projects"])
api_router.include_router(webhooks_router, tags=["Webhooks"])
if imports_router is not None:
    api_router.include_router(imports_router, tags=["Imports"])
api_router.include_router(gap_analysis_router, tags=["Gap Analysis"])
api_router.include_router(security_router, tags=["Security"])
api_router.include_router(launcher_router, tags=["Launcher"])
api_router.include_router(tracing_router, tags=["Tracing"])
api_router.include_router(triage_router, tags=["Triage Collaboration"])
api_router.include_router(assignments_router, tags=["Assignments"])
api_router.include_router(evasion_router, tags=["Evasion Telemetry"])
api_router.include_router(compliance_router, tags=["Compliance"])
api_router.include_router(forensics_trace_router, tags=["Forensics Trace"])
api_router.include_router(access_logs_router, tags=["Access Logs"])
api_router.include_router(evidence_custody_router, tags=["Evidence Custody"])
