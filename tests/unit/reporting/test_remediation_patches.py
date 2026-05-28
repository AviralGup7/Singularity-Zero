"""Unit tests for the Remediation Patch Generator."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from src.reporting.remediation_patches import RemediationPatchGenerator


def test_remediation_patch_generator_flow():
    """Verify that RemediationPatchGenerator maps findings and dumps patches correctly."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        output_path = Path(tmp_dir)
        generator = RemediationPatchGenerator(output_path)

        target = "test-target.com"
        findings = [
            {
                "title": "SQL Injection in User Search",
                "category": "sql_injection",
                "severity": "critical",
            },
            {
                "title": "Stored Cross-Site Scripting",
                "category": "xss",
                "severity": "high",
            },
            {
                "title": "CORS Wildcard Allowed Origin",
                "category": "cors",
                "severity": "medium",
            },
            {
                "title": "Missing Anti-CSRF Protection",
                "category": "csrf",
                "severity": "medium",
            },
            {
                "title": "Some unknown bug",
                "category": "unknown_cat",
                "severity": "low",
            },
        ]

        patches = generator.generate_patches(target, findings)

        # There should be 5 compiled patches matching categories
        assert len(patches) == 5

        # Check SQL Injection patch content
        sql_patch = next(p for p in patches if "sql" in p["category"].lower())
        assert sql_patch["title"] == "Parameterize SQL Queries"
        assert "cursor.execute" in sql_patch["remediation_code"]

        # Check CSRF patch content
        csrf_patch = next(p for p in patches if "csrf" in p["category"].lower())
        assert csrf_patch["title"] == "Validate Anti-CSRF Tokens"

        # Verify output json file exists and can be parsed
        patches_json_file = output_path / "remediation_patches.json"
        assert patches_json_file.exists()

        with open(patches_json_file, encoding="utf-8") as f:
            data = json.load(f)

        assert len(data) == 5
        assert data[0]["target"] == target
