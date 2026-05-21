import json
from pathlib import Path

from src.reporting.report_artifacts import (
    build_report_library,
    verify_report_package,
    write_report_package,
)


def test_write_report_package_creates_signed_compliance_artifacts(tmp_path: Path) -> None:
    target_root = tmp_path / "example.com"
    run_dir = target_root / "run-001"
    run_dir.mkdir(parents=True)
    (run_dir / "report.html").write_text("<!doctype html><title>report</title>", encoding="utf-8")
    compliance = {
        "framework_coverage": {
            "OWASP Top 10 (2021)": {
                "A03:2021-Injection": {
                    "control_id": "A03:2021-Injection",
                    "findings": [],
                    "maturity": "PASS",
                    "recommendation": "Keep validating input handling.",
                }
            }
        },
        "category_counts": {"injection": 1},
        "total_findings": 1,
    }
    summary = {
        "target_name": "example.com",
        "generated_at_utc": "2026-05-21T12:00:00Z",
        "counts": {"urls": 2, "validation_results": 1},
        "scan_quality": {"overall_quality_score": 90},
        "compliance": compliance,
        "tool_availability": {"nuclei": True},
    }
    findings = [
        {
            "title": "Reflected XSS",
            "category": "xss",
            "severity": "high",
            "url": "https://example.com/search?q=x",
        }
    ]

    manifest = write_report_package(
        run_dir=run_dir,
        target_name="example.com",
        summary=summary,
        findings=findings,
    )

    assert (run_dir / "report.json").exists()
    assert (run_dir / "sbom.cdx.json").exists()
    assert (run_dir / "attestation.html").exists()
    assert (run_dir / "attestation.pdf").read_bytes().startswith(b"%PDF-1.4")
    assert (run_dir / "report_manifest.sig").exists()
    assert manifest["signature"]["algorithm"] == "Ed25519"
    verification = verify_report_package(run_dir)
    assert verification["valid"] is True

    report = json.loads((run_dir / "report.json").read_text(encoding="utf-8"))
    assert report["schema_version"].endswith("compliance-report.v1")
    assert report["findings"][0]["id"].startswith("finding-")


def test_build_report_library_exposes_versions_and_links(tmp_path: Path) -> None:
    target_root = tmp_path / "example.com"
    run_dir = target_root / "run-002"
    run_dir.mkdir(parents=True)
    (run_dir / "report.html").write_text("<!doctype html><title>report</title>", encoding="utf-8")
    summary = {
        "target_name": "example.com",
        "generated_at_utc": "2026-05-21T12:00:00Z",
        "counts": {"validation_results": 0},
        "compliance": {"framework_coverage": {}, "total_findings": 0},
    }
    (run_dir / "run_summary.json").write_text(json.dumps(summary), encoding="utf-8")
    write_report_package(
        run_dir=run_dir,
        target_name="example.com",
        summary=summary,
        findings=[],
    )

    library = build_report_library(tmp_path)

    assert library["total"] == 1
    item = library["reports"][0]
    assert item["target"] == "example.com"
    assert item["signature_valid"] is True
    assert item["links"]["attestation_pdf"] == "/reports/example.com/run-002/attestation.pdf"
