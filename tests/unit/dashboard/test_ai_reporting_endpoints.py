"""Unit tests for AI finding explainability and executive summary generation."""

from __future__ import annotations

import pytest
from src.analysis.intelligence.finding_explainer import (
    generate_finding_explanations,
    generate_executive_run_summary,
)


def test_generate_finding_explanations():
    finding = {
        "id": "finding-123",
        "title": "SQL Injection in User Login",
        "severity": "critical",
        "category": "injection",
        "url": "https://example.com/login",
        "evidence": "' OR 1=1 --",
        "description": "Unescaped parameter passed to raw SQL query",
    }
    result = generate_finding_explanations(finding)
    assert result["finding_id"] == "finding-123"
    assert result["severity"] == "critical"
    assert "personas" in result
    assert "developer" in result["personas"]
    assert "auditor" in result["personas"]
    assert "executive" in result["personas"]
    assert "remediation_snippet" in result
    assert "injection" in result["personas"]["developer"]


def test_generate_executive_run_summary():
    findings = [
        {"id": "1", "title": "SQLi", "severity": "critical", "category": "injection"},
        {"id": "2", "title": "XSS", "severity": "high", "category": "xss"},
        {"id": "3", "title": "CORS", "severity": "medium", "category": "exposure"},
    ]
    summary = generate_executive_run_summary(findings, target="example.com", run_id="run-001")
    assert summary["target"] == "example.com"
    assert summary["run_id"] == "run-001"
    assert summary["total_findings"] == 3
    assert summary["severity_breakdown"]["critical"] == 1
    assert summary["severity_breakdown"]["high"] == 1
    assert summary["severity_breakdown"]["medium"] == 1
    assert summary["posture"] == "Critical Risk"
    assert summary["risk_index"] == 17
    assert len(summary["recommendations"]) > 0
