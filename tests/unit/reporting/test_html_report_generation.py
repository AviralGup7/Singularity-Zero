"""Tests for HTML report generation.

Covers template rendering, page generation, and asset inclusion
for both run reports and dashboard index pages.
"""

from pathlib import Path
from typing import Any

import pytest

from src.reporting.html import (
    INDEX_STYLES,
    REPORT_SCRIPT,
    RUN_REPORT_STYLES,
    generate_run_report,
)


class TestReportStyles:
    """Test that report CSS and JS assets are present."""

    def test_run_report_styles_not_empty(self) -> None:
        assert len(RUN_REPORT_STYLES) > 100

    def test_report_script_not_empty(self) -> None:
        assert len(REPORT_SCRIPT) > 100

    def test_index_styles_not_empty(self) -> None:
        assert len(INDEX_STYLES) > 50

    def test_run_report_styles_contains_css_rules(self) -> None:
        assert ":root" in RUN_REPORT_STYLES
        assert "body" in RUN_REPORT_STYLES
        assert "section" in RUN_REPORT_STYLES

    def test_report_script_contains_handlers(self) -> None:
        assert "addEventListener" in REPORT_SCRIPT
        assert "clipboard" in REPORT_SCRIPT

    def test_index_styles_contains_layout(self) -> None:
        assert ".run" in INDEX_STYLES
        assert ".chip" in INDEX_STYLES


class TestGenerateRunReport:
    """Test generate_run_report function."""

    @pytest.fixture
    def minimal_summary(self) -> dict[str, Any]:
        return {
            "target_name": "example.com",
            "generated_at_ist": "2026-01-01 12:00:00",
            "generated_at_utc": "2026-01-01T06:30:00Z",
            "counts": {"urls": 10, "parameters": 5},
            "top_actionable_findings": [],
            "high_confidence_shortlist": [],
            "manual_verification_queue": [],
            "verified_exploits": [],
            "prioritized_endpoints": [],
            "attack_graph": {},
            "endpoint_relationship_graph": [],
            "shared_parameter_tracking": [],
            "auth_context_mapping": [],
            "finding_graph": {},
            "validation_plans": [],
            "target_profile": {},
            "technology_summary": [],
            "attack_surface": {},
            "trend_summary": {},
            "next_steps": [],
            "vrt_coverage": {"entries": []},
            "module_metrics": {},
        }

    def test_generates_report_html(self, tmp_path: Path, minimal_summary: dict[str, Any]) -> None:
        run_dir = tmp_path / "run-001"
        run_dir.mkdir()
        generate_run_report(
            run_dir=run_dir,
            summary=minimal_summary,
            diff_summary=None,
            screenshots=[],
            priority_urls=set(),
            parameters=set(),
            analysis_results={},
        )
        report_file = run_dir / "report.html"
        assert report_file.exists()
        content = report_file.read_text(encoding="utf-8")
        assert "<!doctype html>" in content
        assert "example.com" in content
        assert RUN_REPORT_STYLES[:20] in content
        assert REPORT_SCRIPT[:20] in content

    def test_report_contains_sections(
        self, tmp_path: Path, minimal_summary: dict[str, Any]
    ) -> None:
        run_dir = tmp_path / "run-002"
        run_dir.mkdir()
        generate_run_report(
            run_dir=run_dir,
            summary=minimal_summary,
            diff_summary=None,
            screenshots=[],
            priority_urls=set(),
            parameters=set(),
            analysis_results={},
        )
        content = (run_dir / "report.html").read_text(encoding="utf-8")
        assert "<section>" in content
        assert "<h2>" in content
        assert "</section>" in content

    def test_report_with_diff_summary(
        self, tmp_path: Path, minimal_summary: dict[str, Any]
    ) -> None:
        run_dir = tmp_path / "run-003"
        run_dir.mkdir()
        diff_summary = {
            "previous_run": "/prev/run-001",
            "artifacts": {
                "urls": {
                    "previous_count": 8,
                    "current_count": 10,
                    "added_count": 2,
                    "removed_count": 0,
                    "sample_added": [],
                    "sample_removed": [],
                },
            },
        }
        generate_run_report(
            run_dir=run_dir,
            summary=minimal_summary,
            diff_summary=diff_summary,
            screenshots=[],
            priority_urls=set(),
            parameters=set(),
            analysis_results={},
        )
        content = (run_dir / "report.html").read_text(encoding="utf-8")
        assert "Compared with previous run" in content

    def test_report_first_run_message(
        self, tmp_path: Path, minimal_summary: dict[str, Any]
    ) -> None:
        run_dir = tmp_path / "run-004"
        run_dir.mkdir()
        generate_run_report(
            run_dir=run_dir,
            summary=minimal_summary,
            diff_summary=None,
            screenshots=[],
            priority_urls=set(),
            parameters=set(),
            analysis_results={},
        )
        content = (run_dir / "report.html").read_text(encoding="utf-8")
        assert "first recorded run" in content

    def test_report_with_priority_urls(
        self, tmp_path: Path, minimal_summary: dict[str, Any]
    ) -> None:
        run_dir = tmp_path / "run-005"
        run_dir.mkdir()
        generate_run_report(
            run_dir=run_dir,
            summary=minimal_summary,
            diff_summary=None,
            screenshots=[],
            priority_urls={"https://example.com/api/v1", "https://example.com/login"},
            parameters={"id", "token"},
            analysis_results={},
        )
        content = (run_dir / "report.html").read_text(encoding="utf-8")
        assert "Priority Endpoints" in content
        assert "example.com/api/v1" in content

    def test_report_with_analysis_results(
        self, tmp_path: Path, minimal_summary: dict[str, Any]
    ) -> None:
        run_dir = tmp_path / "run-006"
        run_dir.mkdir()
        analysis_results = {
            "sensitive_data_scanner": [{"url": "https://example.com", "finding": "email"}],
            "token_leak_detector": [{"url": "https://example.com/auth", "token": "leaked"}],
        }
        generate_run_report(
            run_dir=run_dir,
            summary=minimal_summary,
            diff_summary=None,
            screenshots=[],
            priority_urls=set(),
            parameters=set(),
            analysis_results=analysis_results,
        )
        content = (run_dir / "report.html").read_text(encoding="utf-8")
        assert "Sensitive Data Scanner" in content
        assert "Token Leak Detector" in content


class TestBuildDashboardIndex:
    """Test build_dashboard_index function."""

    def test_creates_index_html(self, tmp_path: Path) -> None:
        target_root = tmp_path / "target"
        target_root.mkdir()
        run_dir = target_root / "run-001"
        run_dir.mkdir()
        summary = {
            "target_name": "example.com",
            "generated_at_ist": "2026-01-01 12:00:00",
            "counts": {"urls": 10, "parameters": 5},
        }
        import json

        (run_dir / "run_summary.json").write_text(json.dumps(summary), encoding="utf-8")
        from src.reporting.pages import build_dashboard_index as _build

        _build(target_root, [run_dir])
        index_file = target_root / "index.html"
        assert index_file.exists()
        content = index_file.read_text(encoding="utf-8")
        assert "<!doctype html>" in content
        assert "Dashboard" in content
        assert INDEX_STYLES[:20] in content

    def test_empty_dashboard(self, tmp_path: Path) -> None:
        target_root = tmp_path / "empty-target"
        target_root.mkdir()
        from src.reporting.pages import build_dashboard_index as _build

        _build(target_root, [])
        content = (target_root / "index.html").read_text(encoding="utf-8")
        assert "No runs yet" in content
