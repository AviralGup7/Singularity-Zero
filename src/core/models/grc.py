"""
Pydantic models for GRC (Governance, Risk, and Compliance) Telemetry.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Optional

from pydantic import BaseModel, Field


class ComplianceFramework(StrEnum):
    OWASP_TOP_10 = "OWASP Top 10"
    PCI_DSS = "PCI DSS v4.0"
    SOC2 = "SOC2 TSC"
    ISO_27001 = "ISO 27001:2022"
    NIST_800_53 = "NIST SP 800-53"


class ControlMaturity(StrEnum):
    PASS = "PASS"
    PARTIAL = "PARTIAL"
    AT_RISK = "AT_RISK"
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"


class GRCControl(BaseModel):
    control_id: str
    framework: ComplianceFramework
    maturity: ControlMaturity = ControlMaturity.UNKNOWN
    findings_count: int = 0
    sla_breached: bool = False
    recommendation: Optional[str] = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class GRCReport(BaseModel):
    overall_score: float = 0.0
    band: str = "FAIL"
    evaluated_controls: list[GRCControl] = Field(default_factory=list)
    framework_summaries: dict[ComplianceFramework, dict[str, Any]] = Field(default_factory=dict)
    total_findings: int = 0
