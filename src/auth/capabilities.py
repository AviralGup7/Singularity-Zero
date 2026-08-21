"""Capability catalog and role matrix."""

from __future__ import annotations

from collections.abc import Iterable
from enum import StrEnum

from src.auth.session import capabilities_for_role


class Capability(StrEnum):
    VIEW_FINDINGS = "viewFindings"
    VIEW_JOBS = "viewJobs"
    VIEW_TARGETS = "viewTargets"
    VIEW_AUDIT_LOGS = "viewAuditLogs"
    TRIAGE_FINDINGS = "triageFindings"
    LAUNCH_JOBS = "launchJobs"
    STOP_JOBS = "stopJobs"
    EXPORT_REPORTS = "exportReports"
    MANAGE_KEYS = "manageKeys"
    MODIFY_SETTINGS = "modifySettings"
    VIEW_PII = "viewPII"
    MANAGE_USERS = "manageUsers"


ROLE_MATRIX: dict[str, frozenset[str]] = {
    "guest": frozenset({Capability.VIEW_FINDINGS.value}),
    "viewer": frozenset(
        {
            Capability.VIEW_FINDINGS.value,
            Capability.VIEW_JOBS.value,
            Capability.VIEW_TARGETS.value,
        }
    ),
    "analyst": frozenset(
        {
            Capability.VIEW_FINDINGS.value,
            Capability.VIEW_JOBS.value,
            Capability.VIEW_TARGETS.value,
            Capability.VIEW_AUDIT_LOGS.value,
            Capability.TRIAGE_FINDINGS.value,
            Capability.LAUNCH_JOBS.value,
            Capability.STOP_JOBS.value,
            Capability.EXPORT_REPORTS.value,
        }
    ),
    "operator": frozenset(
        {
            Capability.VIEW_FINDINGS.value,
            Capability.VIEW_JOBS.value,
            Capability.VIEW_TARGETS.value,
            Capability.VIEW_AUDIT_LOGS.value,
            Capability.TRIAGE_FINDINGS.value,
            Capability.LAUNCH_JOBS.value,
            Capability.STOP_JOBS.value,
            Capability.EXPORT_REPORTS.value,
            Capability.VIEW_PII.value,
        }
    ),
    "admin": frozenset(item.value for item in Capability),
    "team_lead": frozenset(
        {
            Capability.VIEW_FINDINGS.value,
            Capability.VIEW_JOBS.value,
            Capability.VIEW_TARGETS.value,
            Capability.VIEW_AUDIT_LOGS.value,
            Capability.TRIAGE_FINDINGS.value,
            Capability.LAUNCH_JOBS.value,
            Capability.EXPORT_REPORTS.value,
            Capability.VIEW_PII.value,
        }
    ),
}


def matrix_capabilities(role: str) -> frozenset[str]:
    normalized = str(role or "viewer").strip().lower()
    if normalized in ROLE_MATRIX:
        return ROLE_MATRIX[normalized]
    return capabilities_for_role(normalized)


def missing_capabilities(role: str, required: Iterable[str]) -> frozenset[str]:
    have = matrix_capabilities(role)
    return frozenset(item for item in required if item not in have)


def can(role: str, capability: str) -> bool:
    return capability in matrix_capabilities(role)
